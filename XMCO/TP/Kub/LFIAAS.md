![[IMG-20260629145303423.png]]

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin

```

```
/var/run/secrets/kubernetes.io/serviceaccount/token

eyJhbGciOiJSUzI1NiIsImtpZCI6InRFYXh5NlBxYkZCUHhKeUJ3aXktMGFjc3VDdWFsUzVYbFh3ZkF3UFI3SDAifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJya2UyIl0sImV4cCI6MTgxNDI3MjQ5MiwiaWF0IjoxNzgyNzM2NDkyLCJpc3MiOiJodHRwczovL2t1YmVybmV0ZXMuZGVmYXVsdC5zdmMuY2x1c3Rlci5sb2NhbCIsImp0aSI6IjM2OTU1OGQ2LWQxNTctNDA4NS1iNjZmLWJhNzJjYWQ0NDAzNyIsImt1YmVybmV0ZXMuaW8iOnsibmFtZXNwYWNlIjoic2VydmljZXMiLCJub2RlIjp7Im5hbWUiOiJ4bWt1Yi13b3JrZXIiLCJ1aWQiOiJjZjdjN2NhMy1lZmNiLTQxNGItYjRmMC0zNGQ2N2JjNzE2NjgifSwicG9kIjp7Im5hbWUiOiJsZmlhYXMtYmFjay1kZXBsb3ltZW50LTVjNmI1N2NmZjYtNXI2bDQiLCJ1aWQiOiJiNzFkZTAzNy0wNjQ4LTQ4YTgtYTQyZi01ZjJkMmFiZGU4YzMifSwic2VydmljZWFjY291bnQiOnsibmFtZSI6ImxmaWFhcyIsInVpZCI6IjkwOTRkNzFhLTJmNDItNGY0NC1hYWYyLWEyOGFjZjIxYjk0NCJ9LCJ3YXJuYWZ0ZXIiOjE3ODI3NDAwOTl9LCJuYmYiOjE3ODI3MzY0OTIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpzZXJ2aWNlczpsZmlhYXMifQ.R0hFDcX2z3QglreOI6yOzXhIFHhSbe88WQ8xrLgTRJyWuYg6tQ11jmeDdrZfhsJsE_D29mBkqGuOC_wpBYOnQVyJ7K1ETecKYJsmZQCV7B_RJbZhxSStjkZNmMRqF5kejIGiJyaJUN7B97_P7V4558jfuavyV_0v-mAH_GqIWw8MVKmZLppndgPI0SqUnk-LenEvnw_XfEPUmSgO88UQww4DXG_ZjyJPdl6boc-atprjn_Nx1NpTGeFCJ_AGrUM5UdxvPdnb-vrhk3gDIU74CKvkSHxA_N0_VRcjdQ6RFRDxCABX9DMdpfLrSP3kUqB98sa14Ybnq_msKF3nTuuxxQ
```

```bash
var/run/secrets/kubernetes.io/serviceaccount/namespace

services
```

```
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

-----BEGIN CERTIFICATE-----
MIIBeTCCAR+gAwIBAgIBADAKBggqhkjOPQQDAjAkMSIwIAYDVQQDDBlya2UyLXNl
cnZlci1jYUAxNzgyNzE5NDkyMB4XDTI2MDYyOTA2NTEzMloXDTM2MDYyNjA2NTEz
MlowJDEiMCAGA1UEAwwZcmtlMi1zZXJ2ZXItY2FAMTc4MjcxOTQ5MjBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABG6J74pcTxy8ovAiCFOR2ZhCdc0XmnlA0iZK5lz2
0yK7Hg2jTorbbccVsGw0g74NGd94Yb5TFgjf7Udc7nWIXxOjQjBAMA4GA1UdDwEB
/wQEAwICpDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR8gx4qqaSg2AXyyN6y
x6cF2ppM7TAKBggqhkjOPQQDAgNIADBFAiAqe1ma3hTlbM6ZQ4y7IKXJsOUJM8jP
Ubwtex5oN1jdQwIhAJF/5k2YiUxqTgZvzHG6FhntDAaeZG/VK6phIAdC3AOV
-----END CERTIFICATE-----
```




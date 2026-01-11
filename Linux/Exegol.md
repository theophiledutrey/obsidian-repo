# Exegol-history (exh) — Cheat Sheet

Outil : gestion de credentials & hôtes pour CTF / pentest (Exegol)

---

## 📦 Ajouter des credentials

```bash
exh add creds -u 'USER' -p 'PASSWORD' -d 'DOMAIN'
```

Avec hash NTLM :

```bash
exh add creds -u 'USER' -H 'NT_HASH' -d 'DOMAIN'
```

Avec password + hash :

```bash
exh add creds -u 'USER' -p 'PASSWORD' -H 'NT_HASH' -d 'DOMAIN'
```

---

## 🖥️ Ajouter un hôte

```bash
exh add hosts --ip 'IP' -n 'HOSTNAME' -r 'ROLE'
```

Exemple :

```bash
exh add hosts --ip '10.10.10.10' -n 'dc.corp.local' -r 'DC'
```

---

## 📥 Importer des credentials (CSV)

```bash
exh import creds --file creds.csv --format CSV
```

---

## 🎛️ Sélectionner un contexte (TUI)

### Sélection interactive de credentials

```bash
exh set creds
```

### Sélection interactive d’hôtes

```bash
exh set hosts
```

---

## 🔍 Voir le contexte actif

```bash
exh show
```


---

## 🗑️ Supprimer des credentials



```bash
exh rm creds --id 1
exh rm creds --id 1,2,3
```

---

## 🧹 Nettoyer le shell (IMPORTANT)

### Retirer le contexte Exegol-history

```bash
exh unset creds
```

### Reset complet du shell

```bash
exec $SHELL
```

---

## ⚠️ Nettoyage manuel (si variables non préfixées)

Si `USER`, `DOMAIN`, `PASSWORD` sont encore définies :

```bash
unset USER DOMAIN PASSWORD
exec $SHELL
```

---

## 🔧 Utilisation avec des outils

### CrackMapExec (password)

```bash
cme smb $EXH_IP -u $EXH_USER -p $EXH_PASS -d $EXH_DOMAIN
```

### CrackMapExec (hash)

```bash
cme smb $EXH_IP -u $EXH_USER -H $EXH_HASH -d $EXH_DOMAIN
```

---

## 🧪 Workflow recommandé

```bash
exh add creds
exh add hosts
exh set creds
exh set hosts
exh show
# attaques
exh rm creds
exh unset creds
exec $SHELL
```
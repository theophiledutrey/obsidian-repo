# 1. Prérequis

Outils nécessaires sur la machine d’analyse :

- **Android Emulator** (Android Studio / AVD)
- **ADB (Android Debug Bridge)**
- **Python3**
- **Frida tools**

Installation de Frida sur la machine :

```bash
pip install frida-tools
```

Vérifier l'installation :

```bash
frida --version
```

---

# 2. Vérifier que l’émulateur est accessible via ADB

Lister les appareils connectés :

```bash
adb devices
```

Exemple de résultat :

```
List of devices attached
emulator-5554   device
```

Si l’émulateur apparaît, ADB est correctement connecté.

---

# 3. Vérifier si l’émulateur est root

Entrer dans le shell Android :

```bash
adb shell
```

Puis :

```bash
whoami
```

Si le résultat est :

```
root
```

alors l’émulateur est rooté (ce qui est souvent le cas des émulateurs Android).

---

# 4. Télécharger Frida Server

Aller sur le repository officiel :

https://github.com/frida/frida/releases

Télécharger la version correspondant à :

- la **version de Frida installée**
- l’architecture **x86 / x86_64** (émulateur)

Exemple :

```
frida-server-16.x.x-android-x86_64.xz
```

---

# 5. Extraire le binaire

```bash
xz -d frida-server-*.xz
```

Renommer (optionnel mais pratique) :

```bash
mv frida-server-* frida-server
```

---

# 6. Envoyer Frida Server dans l’émulateur

```bash
adb push frida-server /data/local/tmp/
```

---

# 7. Donner les permissions d’exécution

```bash
adb shell
```

Puis :

```bash
chmod +x /data/local/tmp/frida-server
```

---

# 8. Lancer Frida Server

Toujours dans le shell Android :

```bash
/data/local/tmp/frida-server &
```

Le `&` permet de lancer le serveur **en arrière-plan**.

---

# 9. Vérifier que Frida fonctionne

Sur la machine d’analyse :

```bash
frida-ps -U
```

Option :

- `-U` → utilise le périphérique USB / ADB

Si tout fonctionne, la liste des applications apparaît.

Exemple :

```
 PID  Name
----  -----------------
1234  com.example.app
2345  system_server
```

---

# 10. Attacher Frida à une application

Lister les apps :

```bash
frida-ps -Uai
```

Attacher Frida :

```bash
frida -U -n com.example.app
```

Ou lancer l’app avec Frida :

```bash
frida -U -f com.example.app
```

---

# 11. Exemple d'utilisation (hook simple)

Script Frida :

```javascript
Java.perform(function() {
    console.log("Frida hooked !");
});
```

Lancer :

```bash
frida -U -f com.example.app -l script.js
```

---

# 12. À quoi sert Frida en pentest mobile

Frida permet de :

- bypass un **login**
- modifier le **résultat d’une fonction**
- bypass **SSL pinning**
- récupérer des **clés secrètes**
- observer les **arguments de fonctions**
- modifier le comportement d'une application **sans modifier l’APK**

C’est un outil central en **reverse engineering Android et pentest mobile**.

---

# 13. Schéma simplifié

```
Machine pentest
      │
      │ Frida client
      │
ADB ──┼────────────────────
      │
      │
Android Emulator
      │
      └── frida-server
            │
            └── Application cible
```

---

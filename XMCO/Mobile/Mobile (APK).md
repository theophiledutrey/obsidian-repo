
# Architecture de l’environnement

PC (Mac / Linux)

- Android Studio
  - Android Emulator
- ADB (Android Debug Bridge)
- Reverse engineering
  - jadx
  - apktool
- Dynamic analysis
  - frida
  - objection
- APK tools
  - zipalign
  - apksigner

---

# Installation des outils nécessaires

## Android Studio

Permet d’obtenir :

- Android Emulator
- Android SDK
- ADB
- zipalign
- apksigner

Téléchargement :
https://developer.android.com/studio

Le SDK est généralement installé dans :

~/Library/Android/sdk

---

## ADB (Android Debug Bridge)

ADB permet de contrôler un appareil Android depuis le PC.

Fonctionnalités principales :

- installer une app
- ouvrir un shell
- lire les logs
- récupérer des fichiers
- lancer une activité

Exemples :

adb devices
adb shell
adb install app.apk
adb logcat

---

## JADX (Reverse engineering Java)

Permet de décompiler un APK en code Java lisible.

Installation :

brew install jadx

Utilisation :

jadx-gui app.apk

Permet de :
- analyser le code
- chercher des clés
- comprendre la logique

---

## APKTool

Permet de décompiler et reconstruire un APK.

Installation :

brew install apktool

Utilisation :

apktool d app.apk
apktool b app

Structure obtenue :

app/
 ├── AndroidManifest.xml
 ├── smali/
 ├── res/
 ├── assets/
 └── lib/

---

## Frida

Frida permet :

- d’instrumenter une application
- de hook des fonctions
- de bypass SSL pinning
- de bypass root detection

Installation :

pip install frida-tools

---

## Objection

Framework basé sur Frida pour faciliter le pentest mobile.

Installation :

pip install objection

---

# Création d’un émulateur Android

Dans Android Studio :

Device Manager → Create Device

Choisir un appareil :

Pixel 4 / Pixel 5 / Pixel 6

---

## ⚠️ Choix important de l’image Android

Toujours choisir :

Google APIs

Ne pas choisir :

Google Play

Pourquoi ?

Google Play → pas rootable
Google APIs → root possible

---

# Lancer l’émulateur

Device Manager → Start

Vérifier la connexion :

adb devices

Exemple :

List of devices attached
emulator-5554 device

---

# Vérifier l’accès shell Android

adb shell

Puis :

whoami

Résultat attendu :

shell

---

# Installation d’un APK

adb install app.apk

Si l'app existe déjà :

adb install -r app.apk

---

# Problème courant : APK non alignée

Erreur possible :

INSTALL_PARSE_FAILED

Solution :

/Users/tdutrey/Library/Android/sdk/build-tools/36.1.0/zipalign -p -f 4 app.apk app_aligned.apk

zipalign optimise la structure ZIP de l’APK.

---

# Problème courant : APK non signée

Android exige qu’une application soit signée.

Erreur :

INSTALL_PARSE_FAILED_NO_CERTIFICATES

---

# Générer un debug keystore

keytool -genkey -v -keystore ~/.android/debug.keystore -storepass android -alias androiddebugkey -keypass android -keyalg RSA -keysize 2048 -validity 10000

---

# Signer l’APK

apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android app_aligned.apk

---

# Installer l’APK signée

adb install app_aligned.apk

---
# Lancer l’application

adb shell monkey -p com.example.app -c android.intent.category.LAUNCHER 1


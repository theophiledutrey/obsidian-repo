<![[IMG-20251218193950781.png]]

Outil pour extraire atidrv.dll:

binwalk
Ressource hacker
PE explorer

---
![[IMG-20251218193950831.png]]
```
HKEY_CLASSES_ROOT
 └─ CLSID
    └─ {3543619C-D563-43F7-95EA-4DA7E1CC396A}
        (Default) = "CodeProject Example BHO"
```
**Ce que ça veut dire :**

- **Hive** : `HKEY_CLASSES_ROOT` → ruche qui contient les définitions de classes COM, associations de fichiers, etc.
- **Clé `CLSID\{GUID}`** : c’est le “dossier” principal qui représente **la classe COM**.
    - `{3543…396A}` = identifiant unique du composant (GUID).

- **Valeur `(Default)` = `"CodeProject Example BHO"`** :
    - nom purement **descriptif**, lisible par un humain (affichage dans certains outils).
    - n’influe pas directement sur le comportement : c’est juste “le label” de ce CLSID.

👉 En clair :
> Ici, la DLL **déclare un nouveau composant COM** identifié par ce GUID, et lui donne un nom lisible “CodeProject Example BHO”.

---

![[IMG-20251218193950860.png]]

```
HKEY_CLASSES_ROOT
 └─ CLSID
    └─ {3543619C-D563-43F7-95EA-4DA7E1CC396A}
        └─ InProcServer32
             (Default)       = "C:\Windows\atidrv.dll"   ← chemin de la DLL
             "ThreadingModel" = "Apartment"
```

**Ce que ça veut dire :**

- **Clé `InProcServer32`** :
    - indique à COM que la classe est un **serveur en-proc**, c.-à-d. implémentée dans une DLL chargée dans le même processus que le client.
- **Valeur `(Default)` = `"C:\Windows\atidrv.dll"`** :
    - c’est l’info **la plus importante** : “Quand quelqu’un demande le CLSID {GUID}, charge la DLL `C:\Windows\atidrv.dll`.”
    - COM utilise cette valeur pour savoir **quel fichier DLL charger**.

- **Valeur `"ThreadingModel" = "Apartment"`** :
    - configuration de COM → modèle de threading **STA (Single Thread Apartment)**.
    - c’est le modèle attendu par Internet Explorer pour ses BHO.
    - nécessaire pour que la création de l’objet COM se fasse correctement.

👉 En clair :

> Ici, la DLL dit à Windows :  “Mon composant COM {GUID} est implémenté dans `C:\Windows\atidrv.dll`,  et il doit être utilisé avec le modèle de threading COM `Apartment`.”

---

![[IMG-20251218193950903.png]]

```
HKEY_LOCAL_MACHINE
 └─ Software
    └─ Microsoft
       └─ Windows
          └─ CurrentVersion
             └─ Explorer
                └─ Browser Helper Objects
                   └─ {3543619C-D563-43F7-95EA-4DA7E1CC396A}
                        "NoExplorer" = 1 (REG_DWORD)
```

**Ce que ça veut dire :**

- **Hive** : `HKEY_LOCAL_MACHINE` → configuration globale au système (tous les utilisateurs).
- **Chemin `...\Browser Helper Objects\{GUID}`** :
    - c’est la liste des **BHO (Browser Helper Objects)** qu’Internet Explorer doit charger.
    - le fait d’ajouter le GUID ici déclare ce composant COM comme **extension IE**.
- **Valeur `"NoExplorer" = 1 (REG_DWORD)`** :
    - option spécifique aux BHO :
        - `1` → ne PAS charger le BHO dans `explorer.exe` (explorateur de fichiers),
        - le garder limité à `iexplore.exe` (Internet Explorer).
    - évite que la DLL soit injectée dans l’explorateur de fichiers Windows.

👉 En clair :

> Ici, la DLL s’enregistre comme **extension de navigateur (BHO)** d’Internet Explorer, valable pour tout le système,  
> et précise que ce composant **ne doit pas être chargé dans Explorer.exe**, seulement dans IE.

---

## cycle de vie d’une DLL COM/BHO

Quand on ouvre IE :

1. IE lit `Browser Helper Objects` → voit ton `{GUID}`
2. COM regarde `HKCR\CLSID\{GUID}\InProcServer32` → trouve `C:\Windows\atidrv.dll`
3. COM fait :
    - `LoadLibrary("atidrv.dll")`
    - appelle `DllMain(hinstDLL, DLL_PROCESS_ATTACH, ...)`
    - appelle `DllGetClassObject(...)`
    - instancie l’objet COM (la classe BHO)
4. Ensuite IE appelle **les méthodes de cet objet** (SetSite, Invoke, etc.)

--- 

![[IMG-20251218193950926.png]]

![[IMG-20251218193950964.png]]

![[IMG-20251218193951001.png]]

![[IMG-20251218193951021.png]]

![[IMG-20251218193951057.png]]

![[IMG-20251218193951084.png]]

![[IMG-20251218193951112.png]]

![[IMG-20251218193951135.png]]

![[IMG-20251218193951167.png]]

![[IMG-20251218193951191.png]]

![[IMG-20251218193951219.png]]

![[IMG-20251218193951252.png]]

![[IMG-20251218193951272.png]]

![[IMG-20251218193951300.png]]

![[IMG-20251218193951337.png]]

![[IMG-20251218193951363.png]]

![[IMG-20251218193951391.png]]



![[IMG-20251218193951434.png]]

![[IMG-20251218193951461.png]]

![[IMG-20251218193951500.png]]

![[IMG-20251218193951533.png]]
![[IMG-20251218193951562.png]]

![[IMG-20251218193951599.png]]


Différent de:

![[IMG-20251218193951625.png]]


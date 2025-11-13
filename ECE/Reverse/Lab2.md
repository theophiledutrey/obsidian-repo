![[IMG-20251113014659959.png]]

Outil pour extraire atidrv.dll:

binwalk
Ressource hacker
PE explorer


![[IMG-20251113014733993.png]]

HKEY_CLASSES_ROOT
 └─ CLSID
    └─ {3543619C-D563-43F7-95EA-4DA7E1CC396A}
        (Default) = "CodeProject Example BHO"

![[IMG-20251113014805915.png]]

HKEY_CLASSES_ROOT
 └─ CLSID
    └─ {3543619C-D563-43F7-95EA-4DA7E1CC396A}
        └─ InProcServer32
             (Default)       = "C:\Windows\atidrv.dll"   ← chemin de la DLL
             "ThreadingModel" = "Apartment"

![[IMG-20251113014843068.png]]

HKEY_LOCAL_MACHINE
 └─ Software
    └─ Microsoft
       └─ Windows
          └─ CurrentVersion
             └─ Explorer
                └─ Browser Helper Objects
                   └─ {3543619C-D563-43F7-95EA-4DA7E1CC396A}
                        "NoExplorer" = 1 (REG_DWORD)

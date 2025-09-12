‍ Student name: Théophile Dutrey, Arthur Berret 
️ Student class: Cyber Groupe 1
 Date: 12/09/2025

# Exercise 1 - Prevent anonymous enumeration of accounts
## Task 1: Assess the existing
### Questions
What nmap commands did you use to perform the enumeration?
![[IMG-20250911173038359.png]]
![[IMG-20250911174136867.png]]

Using the network capture filtered on the SAMR frames, list the SAM remote procedures used by NMap to perform the enumeration.

### SAM remote procedures observées :

![[IMG-20250911174849949.png]]


1. Connect4 – ouvre un handle sur le service SAMR.
2. EnumDomains – énumère les domaines disponibles sur la machine.
3. LookupDomain – résout le SID associé à un nom de domaine (par ex. WIN-SRV1, NORTHWIND).
4. OpenDomain – ouvre un handle sur le domaine précédemment résolu.
5.  QueryDisplayInfo – récupère la liste des comptes (utilisateurs et groupes) avec des infos de base (nom, description, RID, etc.).

## Task 2: Remediate weak SAM remote configuration
### Questions
What settings did you apply to fix the vulnerable environment? List all changes you performed on the configuration. Then, for each parameter, explain why you defined it.

![[IMG-20250912110216267.png]]

1. Network access: Do not allow anonymous enumeration of SAM accounts and shares

Cette option empêche les connexions anonymes de lister les comptes et partages via le service SAM/LSASS. Sans cela, un attaquant pourrait facilement récolter des usernames valides pour lancer des attaques par force brute ou par dictionnaire.

![[IMG-20250912110152513.png]]



2. Network access: Let Everyone permissions apply to anonymous users

Par défaut, le groupe spécial Everyone incluait aussi les connexions anonymes. En désactivant ce paramètre, on évite que des utilisateurs anonymes héritent de permissions prévues pour des comptes authentifiés, réduisant fortement la surface d’attaque.

![[IMG-20250912110310830.png]]



3. Network access: Restrict anonymous access to Named Pipes and Shares

Les pipes nommés sont souvent utilisés par des services Windows (par ex. SMB, RPC). Les bloquer aux anonymes empêche l’ouverture de canaux IPC (Inter-Process Communication) non authentifiés, qui pourraient servir à des escalades ou de l’énumération.

![[IMG-20250912110432834.png]]



4. Suppression de "ANONYMOUS LOGON" du groupe “Pre-Windows 2000 Compatible Access”

Sur un contrôleur de domaine, la base SAM est en réalité l’ADDS. Ici, les sessions anonymes étaient autorisées via l’appartenance du compte “ANONYMOUS LOGON” à ce groupe hérité pour compatibilité avec d’anciens systèmes. En retirant ce membre, on empêche toute session anonyme d’accéder aux ressources AD. 

![[IMG-20250912111621792.png]]

![[IMG-20250912111634788.png]]



## Task 3: Assess remediated configuration
### Questions
Using the network capture, explain how the server is now refusing anonymous enumeration of SAM accounts.

![[IMG-20250912113803202.png]]
Dans cette capture, un scan Nmap avec le script smb-enum-users a été exécuté sur le serveur WIN-SRV1 en utilisant une connexion anonyme (null session).

Avant la remédiation, ce type de requête permettait d’énumérer les comptes du SAM et retournait la liste complète des utilisateurs locaux ou de domaine.

Dans le résultat affiché ici, on constate que le serveur ne retourne plus la liste des utilisateurs : seules les entrées intégrées (Administrator, Guest, DefaultAccount, WDAGUtilityAccount) apparaissent, et toutes les tentatives d’accès aux comptes de domaine échouent.

Cela démontre que :

Les requêtes anonymes sur le port SMB (445/tcp) sont bien interceptées.

Les paramètres de GPO appliqués (interdiction d’énumération SAM, exclusion des anonymes du groupe Everyone, restriction des pipes nommés, suppression de ANONYMOUS LOGON du groupe Pre-Windows 2000 Compatible Access) empêchent désormais l’énumération anonyme.

La réponse du serveur ne fournit plus d’informations exploitables à un attaquant (comme la liste des comptes utilisateurs de domaine), ce qui confirme que la configuration vulnérable a bien été corrigée.
# Exercise 2 - Fill-in-the-gaps – code a simplified whoami utility

## Task 1: Open the project

![[IMG-20250912114424105.png]]

## Task 2: Fill missing code parts

### Questions
Attach the whoami.cpp file with your answer sheet.
![[IMG-20250912122322275.png]]
Cet extrait montre l’ouverture du jeton de sécurité du processus courant. OpenProcessToken(hThisProcess, TOKEN_QUERY, &hMyToken) (après GetCurrentProcess()) rend un handle (hMyToken) qui permettra de lire les informations du jeton (groupes, SIDs, etc.) via GetTokenInformation. Le droit TOKEN_QUERY suffit ici car on ne modifie rien, on ne fait que lister.

![[IMG-20250912122349437.png]]

Ici, on convertit le SID de chaque groupe du jeton en libellés humains avec LookupAccountSidW. L’appel utilise uniquement les variables imposées : le SID courant pTokenGroups->Groups[i].Sid, les buffers wszName et wszDomain (tailles dwNameSize, dwDomainSize), et retourne le type dans sidType. En cas de succès, on peut afficher Domaine\Nom du groupe au lieu d’un SID brut.

![[IMG-20250912122637475.png]]

Le programme liste les groupes du jeton : on voit des noms traduits (ex. NORTHWIND\Domain Users, BUILTIN\Users, NT AUTHORITY\Authenticated Users) avec leurs SIDs. Cela prouve que l’ouverture du jeton, l’énumération (GetTokenInformation) et la traduction SID→nom fonctionnent correctement. Le code de sortie 0 confirme une exécution sans erreur.
# Exercise 3 - Observe the effects of UAC
## Task 1: Token of administrator accounts
### Questions
Using only the whoami output, how can you tell if the current user is the built-in Administrator account?
On ne se base pas sur le nom du compte, mais sur son SID. L’Administrateur intégré a toujours le RID 500 : le SID se termine donc par …-500 (ex. S-1-5-21-<DomainOrMachineSID>-500). Si le SID affiché par whoami /all se termine par 500, l’utilisateur courant est le compte Administrateur intégré, même s’il a été renommé.

Is the current user the built-in Administrator account?
Non. Dans la sortie whoami /all fournie, le SID de l’utilisateur se termine par …-1001 (et non …-500). Cela signifie qu’il s’agit d’un autre compte (ici “karen”), pas du compte Administrateur intégré.

From the whoami output, what is the meaning of the "Group used for deny only" attribute for the BUILTIN\Administrators alias?
Cet attribut indique que l’utilisateur est bien membre de BUILTIN\Administrators, mais que, dans ce jeton, ce groupe est désactivé pour les autorisations (token UAC “restreint”). Son SID ne sert qu’à évaluer des règles deny et ne donne aucun droit d’administrateur tant que le processus n’est pas élevé (“Run as administrator”), cas dans lequel le groupe apparaîtra comme Enabled group.






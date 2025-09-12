‍ Student name: ……………………………………………………………………………………………………………………………....
️ Student class: ……………………………………………………………………………………………………………………………......
 Date: ……………………………………………………………………………………………………………………………....................

## Exercise 1 - Prevent anonymous enumeration of accounts
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
## Exercise 2 - Fill-in-the-gaps – code a simplified whoami utility

## Task 1: Open the project

![[IMG-20250912114424105.png]]

## Task 2: Fill missing code parts
### Questions
Attach the whoami.cpp file with your answer sheet.

## Exercise 3 - Observe the effects of UAC
## Task 1: Token of administrator accounts
### Questions
Using only the whoami output, how can you tell if the current user is the built-in Administrator account?
Is the current user the built-in Administrator account?
From the whoami output, what is the meaning of the "Group used for deny only" attribute for the BUILTIN\Administrators alias?

## Task 2: Token of administrator accounts
### Questions
Explain why attempting to access the folder resulted in a dialog box informing you that don't have access to the folder.
What happened to the folder's DACL when you clicked on Continue?
Explain why the change in the DACL was necessary

## Task 3: Token of a built-in Administrator account
### Questions
From the whoami output, how can you tell that the current user is a built-in Administrator user account?
How the BUILTIN\Administrators group is processed differently for this user?
## Exercise 4 - Configure a service to use a gMSA
## Task 2: Create a gMSA account in the Active Directory domain
### Questions
Copy-paste here the commands used to accomplish the task and their respective output. For each command, explain its role and why it is needed.

## Task 3: Assign gMSA to the IIS application pool
### Questions
Explain the benefits of using a gMSA instead of a standard user account or the computer's identity.





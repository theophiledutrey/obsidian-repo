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

![[IMG-20250912110152513.png]]

![[IMG-20250912110310830.png]]

![[IMG-20250912110432834.png]]



## Task 3: Assess remediated configuration
### Questions
Using the network capture, explain how the server is now refusing anonymous enumeration of SAM accounts.
## Exercise 2 - Fill-in-the-gaps – code a simplified whoami utility
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





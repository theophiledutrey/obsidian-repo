Vuln:

1) ADCS ESC 1, 4, 8
2) CALADAN -> wwwroot write + Guest 
3) ACL
4) Mdp faible
5) AS-REP roasting
6) Kerberoasting
7) Privesc via PrintSpoofer64.exe

Au moins trois défauts de configuration au sein du module ADCS permettent à un attaquant d'élever ses privilèges jusqu'au niveau administrateur du domaine, entraînant la compromission complète de l'environnement Active Directory. Critique

Au moins deux défauts de configuration sur le serveur CALADAN permettent à un attaquant non authentifié de manipuler les fichiers du serveur web et d'exécuter du code arbitraire, aboutissant à la compromission du système. Critique

Au moins quatre défauts de contrôle d'accès sur les objets Active Directory permettent à un attaquant d'élever ses privilèges, aboutissant à la compromission complète du domaine. Majeure 

La présence d'au moins trois comptes avec des identifiants faibles permet à un attaquant de compromettre ces comptes, entraînant un accès non autorisé aux ressources de l'environnement Active Directory. Majeure (mettre un point positi sur le ban du comptes au bout d un certain nombre de tentative)

La présence d'au moins un compte avec la pré-authentification Kerberos désactivée permet à un attaquant de récupérer un hash d'authentification sans interaction avec la cible (AS-REP Roasting), entraînant une exposition des credentials du compte à des tentatives de cassage hors ligne. Majeure

La présence d'au moins quatre comptes avec l'attribut SPN activé permet à un attaquant de récupérer des tickets de service Kerberos chiffrés (Kerberoasting), entraînant une exposition des identifiants de service à des tentatives de cassage hors ligne. Majeure 

La présence de privilèges d'usurpation d'identité (SeImpersonatePrivilege) sur au moins deux serveurs permet à un attaquant d'élever ses privilèges jusqu'au niveau SYSTEM, entraînant la compromission complète des serveurs concernés. Modérée 


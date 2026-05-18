Vuln:

1) ADCS ESC 1, 4, 8
2) CALADAN -> wwwroot write + Guest 
3) ACL
4) Mdp faible
5) AS-REP roasting
6) Kerberoasting
7) Privesc via PrintSpoofer64.exe

Au moins 3 défauts de configuration au sein du module ADCS de l'Active Directory permettent à un attaquant d'élever ses privilèges et de prendre le contôle du domaien

Au moins 2 défauts de configuration sur le serveur CALADAN permettent à un attaquant non authentifié de manipuler les fichiers du serveur web et d'exécuter du code arbitraire, aboutissant à la compromission du système

Au moins 4 défauts de contôle d'accès entre les objets de l'active directory permettent à un attaquant d'élever ses privilèges et de prendre le contôle du domaien
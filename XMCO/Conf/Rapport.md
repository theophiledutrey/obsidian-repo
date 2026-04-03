
| Champ                         | Contenu                                                                                                                                                                                                                                                                                                                             |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Criticité**                 | Critique / Majeure / Modérée / Mineure                                                                                                                                                                                                                                                                                              |
| **Difficulté d’exploitation** | Sophistiquée / Avancée / Intermédiaire / Triviale                                                                                                                                                                                                                                                                                   |
| **Impact métier**             | Faible / Moyen / Important / Vital                                                                                                                                                                                                                                                                                                  |
| **Risque(s)**                 | → Risque                                                                                                                                                                                                                                                                                                                            |
| **Critère(s) d’audit**        | →                                                                                                                                                                                                                                                                                                                                   |
| **Prérequis d’exploitation**  | Boîte noire / Boîte grise <br> Type de compte requis, IP d’origine, whitelisting (NAC, WAF, ouverture de flux sur le SI, etc.)                                                                                                                                                                                                      |
| **Système(s) impacté(s)**     | → Système 1 (si plusieurs environnements, le préciser) <br> → Système 2 (si plusieurs environnements, le préciser)                                                                                                                                                                                                                  |
| **Recommandation(s)**         | **TIE/TII/TIS-R1 – Recommandation courte** <br> Recommandation plus détaillée. <br><br> **TIE/TII/TIS-R2 – Recommandation courte** <br> Recommandation plus détaillée. <br><br> **TIE/TII/TIS-R3 – Recommandation courte** <br> Recommandation plus détaillée. <br><br> ```html <p>Exemple de code pour les recommandations</p> ``` |
| **Référence(s) technique(s)** | À REMPLIR AVEC 3.1 À SUPPRIMER UNE FOIS QUE LE RAPPORT EST TERMINÉ                                                                                                                                                                                                                                                                  |
| **Pièce(s) jointe(s)**        | Le fichier vidéo suivant accompagne le rapport afin d’illustrer l’exploitation de la vulnérabilité : <br> XMCO-CODE_PROJET-TITRE_PROJET-VX-NOM_VULN.mp4                                                                                                                                                                             |
|                               |                                                                                                                                                                                                                                                                                                                                     |
###  Critiques



1. **Utilisation d’un système d’exploitation obsolète et non maintenu exposant le serveur à des vulnérabilités connues**  
2. **Exposition de services applicatifs root vulnérables (JBoss, Apache) reposant sur des versions obsolètes**  
3. **Activation de l’authentification SSH par mot de passe facilitant les attaques par force brute**  

---

###  Élevées


4. **Présence de fichiers de confiance `.rhosts` permettant des authentifications sans mot de passe**  
5. **Politique de mots de passe insuffisamment robuste (longueur minimale faible et absence d’expiration)**  
6. **Exposition de bases de données (MySQL, PostgreSQL) accessibles sur le réseau pour tout le monde**  
7. **Utilisation de versions anciennes de composants système (curl, wget, gcc, bash) exposant à des vulnérabilités connues**

---

###  Moyennes
8. **Présence de nombreux comptes systèmes ou applicatifs facilitant les attaques par énumération et bruteforce**  
9. **Surface d’attaque réseau excessive liée à un nombre important de services exposés inutilement**  
10. **Présence de binaires SUID sensibles pouvant permettre une élévation de privilèges locale**  
11. **Absence de mécanismes de confinement applicatif (AppArmor non présent et SELinux potentiellement non appliqué)**  
12. **Présence de services réseau sensibles exposés (Telnet, FTP, NFS) facilitant une compromission à distance**  




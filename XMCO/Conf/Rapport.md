
| Champ                 | Contenu                                                                                                                                                                                                                                                             |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Criticité**         | Critique / Majeure / Modérée / Mineure                                                                                                                                                                                                                              |
| **Risque(s)**         | → Risque                                                                                                                                                                                                                                                            |
| **Description**       |                                                                                                                                                                                                                                                                     |
| **Recommandation(s)** | **TIE/TII/TIS-R1 – Recommandation courte** <br> Recommandation plus détaillée. <br><br> **TIE/TII/TIS-R2 – Recommandation courte** <br> Recommandation plus détaillée. <br><br> **TIE/TII/TIS-R3 – Recommandation courte** <br> Recommandation plus détaillée. <br> |
| **Source**            |                                                                                                                                                                                                                                                                     |

###  Critiques

1. **Utilisation d’un système d’exploitation obsolète et non maintenu exposant le serveur à des vulnérabilités connues**  
2. **Exposition de services applicatifs root vulnérables (JBoss, Apache) reposant sur des versions obsolètes**  
3. **Activation de l’authentification SSH par mot de passe facilitant les attaques par force brute**  

---

###  Élevées

4. **Politique de mots de passe insuffisamment robuste (longueur minimale faible et absence d’expiration)**  
5. **Exposition de bases de données (MySQL, PostgreSQL) accessibles sur le réseau pour tout le monde**  
6. **Utilisation de versions anciennes de composants système (curl, wget, gcc, bash) exposant à des vulnérabilités connues**

---

###  Moyennes

7. **Présence de nombreux comptes systèmes ou applicatifs facilitant les attaques par énumération et bruteforce**  
8. **Surface d’attaque réseau excessive liée à un nombre important de services exposés inutilement**  
9. **Présence de binaires SUID sensibles pouvant permettre une élévation de privilèges locale**  
10. **Absence de mécanismes de confinement applicatif (AppArmor non présent et SELinux potentiellement non appliqué)**  
11. **Présence de services réseau sensibles exposés (Telnet, FTP, NFS) facilitant une compromission à distance**  


## **NC1: L'utilisation d’un système d’exploitation obsolète et non maintenu expose le serveur à des vulnérabilités connues**  

| Champ                 | Contenu                                                                                                                                                                                                                                                             |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Criticité**         | Critique                                                                                                                                                                                                                                                            |
| **Risques**           | → Risque                                                                                                                                                                                                                                                            |
| **Description**       |                                                                                                                                                                                                                                                                     |
| **Recommandation(s)** | **TIE/TII/TIS-R1 – Recommandation courte** <br> Recommandation plus détaillée. <br><br> **TIE/TII/TIS-R2 – Recommandation courte** <br> Recommandation plus détaillée. <br><br> **TIE/TII/TIS-R3 – Recommandation courte** <br> Recommandation plus détaillée. <br> |
| **Source**            |                                                                                                                                                                                                                                                                     |

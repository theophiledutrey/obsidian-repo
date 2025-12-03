![[SOC_Module1 - Définition et rôle.pdf]]

### **SOC = Security Operation Center**
-> Il supervise et répond aux incidents 24/7
-> Equipe dédiée à la surveiilance, la détection, l'analyse et la réponse aux incidents de sécurité

### **Structure d'un soc:**

N1: Surveillance basique et Triage (faux positifs / vrais positifs)
N2: Analyse appronfondie
N3: Réponse à incident

### **Types de SOC**

### 1. SOC Managé:

- **Qui gère ?** Prestataire externe (MSSP/ESN).
- **Rôle :** Supervision 24/7, analyses N1–N3, gestion SIEM/EDR.
- **Client :** Valide actions, applique correctifs.
- **+** Pas besoin d’équipe interne.
- **–** Peu de contrôle, dépendance.


### 2. SOC Co-Managé:

- **Qui gère ?** Partagé client ↔ prestataire.
- **Rôle prestataire :** N1 + support N2/N3.
- **Rôle client :** Analyse/remédiation interne.
- **+** Bon compromis coût/contrôle.
- **–** Nécessite une équipe minimale.


### 3. SOC Interne:

- **Qui gère ?** L’entreprise uniquement.
- **Rôle :** N1–N3, détection, réponse, gestion outils.
- **+** Contrôle total, confidentialité.
- **–** Très coûteux, difficile à maintenir.


### **Outils Principaux du SOC**

- EDR (Endpoint Detection and Response)
- XDR («Extended» Detection & Response)
- SIEM (Security Information and Event Management)
- SOAR (Security Orchestration, Automation and Response)

### **Challenges d’un SOC**

- Volumétrie des incidents: Gérer le nombre d’alertes que le SOC reçoit chaque jour.
- Criticités des incidents: Déterminer le niveau d’importance des incidents
- Classification des incidents: Savoir ce que signifie réellement une alerte.


YARA/SIGMA

Kernel space/User Land/Hooking

Deux exercice pratique

Process trie:
faire du sequentiel

Process trie


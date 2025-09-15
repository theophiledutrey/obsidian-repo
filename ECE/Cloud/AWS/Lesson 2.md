## Objectifs du module

- Expliquer la politique de tarification d’AWS  
- Identifier les caractéristiques fondamentales de la tarification  
- Citer les éléments du coût total de possession (TCO)  
- Discuter des résultats du **Calculateur de prix AWS**  
- Configurer une structure organisationnelle qui simplifie la facturation et la visibilité des comptes  
- Identifier la fonctionnalité du **tableau de bord de facturation AWS**  
- Utiliser **les factures AWS, AWS Cost Explorer, AWS Budgets et le rapport d’utilisation et de coût AWS**  
- Identifier les différents plans et fonctions du **support technique AWS**  

---

## Section 1 : Bases de la tarification

### Modèle de tarification AWS

**Trois facteurs principaux de coût :**
- **Calcul** : facturation à l’heure/seconde (Linux), selon type d’instance.  
- **Stockage** : facturation au Go.  
- **Transfert de données** :  
  - Trafic entrant gratuit (sauf exceptions).  
  - Trafic sortant facturé, regroupé, facturation au Go.  

### Modes de paiement AWS

- **Paiement à l’utilisation** : payer uniquement ce que vous consommez.  
- **Payez moins en réservant** : instances réservées (jusqu’à -75%).  
- **Payez moins en utilisant plus** : tarification progressive (S3, EBS, EFS).  
- **Payez moins à mesure qu’AWS évolue** : baisses régulières de prix (75 entre 2006 et 2019).  

### Offre gratuite AWS

- 1 an gratuit pour les nouveaux clients.  
- Exemples : micro-instance EC2, S3, EBS, ELB, transferts entrants.  

### Services sans frais

- Amazon VPC  
- Elastic Beanstalk  
- Auto Scaling  
- AWS CloudFormation  
- AWS IAM  

⚠️ Les ressources utilisées dans ces services peuvent générer des coûts.  

### Points clés à retenir

- Pas de frais pour transferts **entrants** ni transferts **intra-région**.  
- Pas de contrat à long terme.  
- Paiement à l’utilisation.  
- Démarrage/arrêt à tout moment.  

---

## Section 2 : Coût total de possession (TCO)

### Définition

> Estimation financière permettant d’identifier les **coûts directs et indirects** d’un système.

**Utilité :**
- Comparer les coûts **on-premises vs AWS**.  
- Évaluer une migration vers le cloud.  
- Créer des études de cas budgétaires.  

### Comparaison On-premises vs AWS

**Infrastructure traditionnelle :**
- Coûts fixes (CapEx).  
- Équipements, licences, maintenance.  
- Mise à l’échelle verticale lente et coûteuse.  
- Cycles d’investissement longs.  

**Cloud AWS :**
- Aucune dépense initiale, paiement à l’usage (OpEx).  
- Mise à l’échelle ascendante/descendante.  
- Infrastructure en libre-service.  
- Agilité et réduction du time-to-market.  

### Considérations liées au TCO

- **Serveurs** : matériel, licences, maintenance, électricité.  
- **Stockage** : disques, SAN, administration, énergie.  
- **Réseau** : commutateurs, câblage, bande passante.  
- **Main-d’œuvre** : administration systèmes & réseau.  

### Exemple chiffré

Sur 3 ans, une même infrastructure coûte :  
- **On-premises** : 167 422 USD  
- **AWS (EC2 réservé 3 ans)** : 7 509 USD  
- → Économie : **159 913 USD (-96%)**  

---

## Section 3 : AWS Organizations

### Présentation

Service gratuit pour consolider plusieurs comptes AWS dans une seule **organisation**.  
- Gestion centralisée.  
- Contrôle des accès.  
- Facturation consolidée.  
- Automatisation via API.  

### Terminologie

- **Root** : racine de l’organisation.  
- **OU (Organizational Unit)** : groupe de comptes.  
- **Policy (SCP)** : règles appliquées aux OU ou comptes.  
- **Account** : compte AWS individuel.  

### Avantages & Fonctions

- Politiques de contrôle des services (**SCP**).  
- Groupes de comptes.  
- Automatisation par **API/SDK**.  
- Facturation consolidée (paiement unique, remises sur volume).  

### Sécurité

- **IAM Policies** : contrôlent l’accès **utilisateurs/groupes/roles** à l’intérieur d’un compte.  
- **SCP (Organizations)** : contrôlent l’accès **au niveau du compte/OU** (y compris root).  

### Limites d’AWS Organizations

- Noms ≤ 250 caractères (Unicode).  
- 1 root par organisation.  
- Jusqu’à 1 000 OU.  
- Jusqu’à 1 000 policies.  
- Taille max policy : 5 120 octets.  
- 5 niveaux d’OU max.  
- 20 invitations/jour.  
- 5 créations de comptes simultanées.  
- Attachement de politiques : illimité.  

### Accès à AWS Organizations

- **Console AWS** (navigateur).  
- **AWS CLI** (ligne de commande).  
- **SDK AWS** (Java, Python, .NET, Ruby, etc.).  
- **API HTTPS** (programmation directe).  

---

## Outils de gestion des coûts

### Calculateur de prix AWS

> Permet de modéliser les coûts avant déploiement.

Fonctionnalités :  
- Estimation des coûts mensuels.  
- Identification des réductions possibles.  
- Comparaison de scénarios.  
- Détermination du type d’instances.  
- Organisation en groupes de services.  

### Autres outils (mentionnés dans le module)

- **Tableau de bord de facturation AWS**  
- **AWS Cost Explorer** : analyse des coûts.  
- **AWS Budgets** : suivi des budgets.  
- **Rapports d’utilisation et de coûts**  

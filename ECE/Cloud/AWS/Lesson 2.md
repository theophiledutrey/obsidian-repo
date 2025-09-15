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

---

## Section 4 : Outils de gestion des coûts et facturation

### Tableau de bord de facturation AWS

> Permet de consulter l’état de vos dépenses AWS en cours et de suivre les tendances.

- **Récapitulatif des dépenses** : montre combien a été dépensé le mois précédent, estime les coûts actuels et prédit les dépenses futures.  
- **Dépenses mensuelles par service** : indique la part de chaque service dans les coûts totaux.  

### Outils disponibles

- **AWS Budgets**  
- **Rapport d’utilisation et de coût AWS**  
- **AWS Cost Explorer**  

---

### Factures mensuelles

- Répertorie les coûts encourus par service AWS pour le mois précédent.  
- Ventilation par **région** et par **compte lié**.  
- Inclut la facture mensuelle + distribution détaillée des services utilisés.  

---

### AWS Cost Explorer

> Console de visualisation et d’analyse des coûts.  

- Rapports par défaut pour visualiser les coûts et leur évolution.  
- Prévisions de dépenses (jusqu’à 3 mois).  
- Analyse des coûts par service, par région, par compte.  
- Suivi des 13 mois précédents.  

**Fonctionnalités clés :**
- Identifier les services les plus coûteux.  
- Repérer les tendances et anomalies.  
- Prévoir les dépenses à venir.  
- Filtrer par zone de disponibilité, trafic réseau, comptes les plus actifs.  

---

### AWS Budgets

> Suivi et notifications sur le respect de vos budgets.  

- Basé sur la visualisation des coûts de Cost Explorer.  
- Permet de créer des **alertes de dépassement** via **Amazon SNS**.  
- Budgets suivis sur base **mensuelle, trimestrielle ou annuelle**.  
- Personnalisation des dates de début/fin.  

---

### Rapport d’utilisation et de coût AWS (CUR)

> Fournit une vue complète de l’utilisation AWS.

- Ventilation par **catégorie de service**, **compte**, **utilisateurs**.  
- Détail jusqu’aux **actions API individuelles**.  
- Rapports exportables dans **Amazon S3**.  
- Mise à jour quotidienne possible.  

---

## Section 5 : Support technique AWS

### AWS Support

- Mise à disposition d’**outils et expertise** pour accompagner clients :  
  - Expérimentation.  
  - Production.  
  - Usage stratégique.  

**Types d’assistance :**
- **Technical Account Manager (TAM)** : conseils et suivi proactif.  
- **AWS Trusted Advisor** : recommandations de bonnes pratiques (optimisation coûts, sécurité, tolérance aux pannes).  
- **Support Concierge** : expert en facturation et gestion des comptes.  

---

### Plans de support

- **Basique** :  
  - Gratuit.  
  - Accès documentation, Service Health Dashboard, forums.  
  - Accès limité à Trusted Advisor (6 vérifications).  

- **Développeur** :  
  - Support pour clients en phase de test.  
  - Assistance technique, conseils, accélération des déploiements.  

- **Business** :  
  - 24/7 pour charges de production.  
  - Assistance sur incidents, diagnostic, optimisation.  

- **Enterprise** :  
  - 24/7, pour charges critiques.  
  - Accès TAM, support stratégique, personnalisation avancée.  

---

### Gravité des cas & temps de réponse

| Gravité   | Description                                                                 | Délais de réponse max |
|-----------|-----------------------------------------------------------------------------|------------------------|
| **Critique** | Application critique indisponible, activité compromise.                    | 15 min (Enterprise), 1h (Business) |
| **Urgente**  | Fonction importante affectée.                                              | 1h (Enterprise), 4h (Business) |
| **Élevée**   | Fonction dégradée ou défaillante.                                          | 4h ou moins |
| **Normale**  | Fonction non critique avec comportement anormal ou question générale.      | 12 à 24h |
| **Faible**   | Question générale de développement.                                        | 24h ou moins |

---

## Section 6 : Conclusion du module

### Résumé

- Fondamentaux de la tarification AWS.  
- Concepts du TCO et comparatif On-premises vs Cloud.  
- Estimation avec le **Calculateur de prix AWS**.  
- Suivi via **tableau de bord de facturation, factures, Cost Explorer, Budgets, CUR**.  
- Support AWS : plans, fonctionnalités, délais de réponse.  

### Objectifs atteints

- Compréhension de la politique de tarification AWS.  
- Capacité à comparer les coûts et identifier économies.  
- Connaissance des outils de suivi et optimisation.  
- Maîtrise des offres de support et de leur utilité selon les besoins.  

---

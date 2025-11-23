1) Expliquez brièvement ce qu’est un « pass the hash », et pourquoi utiliser l’évènement 4624. Quels autres évènements pourraient être utiles ici ?
Un Pass-the-Hash (PtH) est une attaque où un adversaire utilise directement le hash NTLM d’un utilisateur pour s’authentifier à sa place, sans connaître son mot de passe en clair. Windows accepte cela car, dans une authentification NTLM, le hash du mot de passe sert déjà de secret.  
Cette technique est couramment utilisée pour le mouvement latéralnou la prise de contrôle d’un compte privilégiénaprès compromission.

L’événement 4624 est utilisé car il correspond à une **authentification réussie**, et dans le cas d’un PtH, plusieurs champs caractéristiques apparaissent :

- **LogonType = 3** → connexion réseau (SMB, WinRM, etc.)
- **AuthenticationPackage = NTLM**
- **LogonProcessName = NtLmSsp**
- **KeyLength = 0** (fréquent en PtH)

D’autres événements pertinents peuvent être :

- **4625** (échecs d’authentification)
- **4648** (logon explicite avec identifiants)
- **4672** (privilèges spéciaux attribués)
- **4776** (NTLM authentications, côté DC)
- **4634** (Déconnnexion)

Pour illustrer le fonctionnement de ma règle Sigma, j’ai d’abord activé SMB sur ma machine virtuelle Windows, puis je me suis connecté au partage depuis ma machine en utilisant la commande suivante :
![[IMG-20251123202805248.png]]

Cette commande établit une authentification réseau NTLM depuis Linux vers Windows. Une fois connecté, j’ai ouvert l’Observateur d’événements sur Windows afin d’examiner les journaux de sécurité. On observe immédiatement une série d’événements caractéristiques, générés automatiquement par Windows lors de la connexion SMB :

![[IMG-20251123202805579.png]]

On retrouve notamment :

- **4624 – Logon** : il s’agit de l’événement principal indiquant une authentification réussie. Dans mon cas, il s’agit d’un **LogonType 3**, ce qui signifie une connexion réseau (typiquement SMB). L’événement montre également que l’authentification s’est faite via **NTLM** et le processus **NtLmSsp**, ce qui correspond exactement aux conditions recherchées par ma règle Sigma.
- **4672 – Special Privileges Assigned** : cet événement apparaît juste avant le 4624 lorsque l’utilisateur possède des privilèges administratifs. Comme mon utilisateur “Théo” est administrateur local, Windows lui attribue automatiquement des privilèges sensibles. Cet événement confirme que la session possède un haut niveau de privilèges, ce qui renforce le risque dans un scénario de Pass-the-Hash.
- **4634 – Logoff** : cet événement signale la fermeture de la session réseau. Il vient compléter le cycle d’authentification en montrant que la session SMB s’est terminée. Ce type d’événement est utile pour corréler les activités d’ouverture et de fermeture de session, et repérer des connexions anormales ou très courtes.

2) Donnez la règle Sigma complète et fonctionnelle. Indiquez quelles clés Sigma vous avez utilisées et pourquoi.

![[IMG-20251123202805778.png]]
![[IMG-20251123202805968.png]]

### **Explication des clés Sigma :**

- **logsource** : indique que la règle s’applique aux logs _Windows Security_.
- **EventID** : 4624 → logon réussi.
- **LogonType** : 3 → logon réseau, typique du PtH.
- **AuthenticationPackageName** : NTLM → authentification NTLM.
- **LogonProcessName** : NtLmSsp → processus NTLM interne.
- **condition** : applique uniquement la sélection.
- **tags** : références MITRE pour contextualiser la détection.

### **Validation automatique de la règle à l’aide de Chainsaw**

Pour vérifier de manière automatique que la règle Sigma fonctionne réellement sur les logs Windows, j’ai utilisé l’outil **Chainsaw**, qui permet d’appliquer des règles Sigma sur des fichiers `.evtx`.  
La commande suivante permet d’analyser le fichier `security.evtx` exporté depuis la machine Windows, en utilisant ma règle Sigma personnalisée et le fichier de mapping fourni par Chainsaw :
![[IMG-20251123202806265.png]]
On observe que la règle s'applique à 8 logs récupéré sur la VM:
![[IMG-20251123202806473.png]]

Voici un exemple parmis les 8 logs ressorties par la commande Chainsaw:
![[IMG-20251123203757697.png]]
Les événements 4624 mis en évidence par Chainsaw correspondent ici à des authentifications NTLM réseau (LogonType = 3) réalisées lorsque je me connecte légitimement au partage SMB depuis ma machine Linux. Ce type d’événement est strictement identique à celui généré lors d’une attaque Pass-the-Hash moderne : Windows ne journalise pas la différence entre une authentification effectuée avec un mot de passe réel et une authentification réalisée directement à partir d’un hash NTLM. Ainsi, même si ma règle Sigma ne permet pas à elle seule de distinguer une connexion légitime d’une véritable attaque Pass-the-Hash, elle reste parfaitement valide et fonctionnelle dans le cadre de ce TP, car elle détecte précisément toutes les ouvertures de session NTLM réseau vers le partage Samba de ma VM. Cela illustre néanmoins une limitation structurelle du journal Windows Security : le Pass-the-Hash ne laisse aucune signature unique dans l’événement 4624, ce qui nécessite en pratique des corrélations supplémentaires pour obtenir une détection fiable.

3) Expliquez synthétiquement la différence conceptuelle entre YARA et Sigma.

**YARA** sert à détecter des patterns dans des fichiers (strings, hex, structures binaires).  
Il s’utilise pour la **détection de malware**, l’analyse mémoire et l'analyse forensique.  
C’est un outil de **détection bas niveau**.

**Sigma**, au contraire, est un langage générique pour décrire des **détections basées sur les logs**.  
Il ne s’applique pas directement : il se **convertit vers des SIEM** (Splunk, Sentinel, ELK…).  
C’est un outil de **détection haut niveau**, orienté activités et comportements.
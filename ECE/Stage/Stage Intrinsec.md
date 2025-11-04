Veille Technologique 

Francais:
**Contexte & découverte**  
Récemment un chercheur (Dirk-jan Mollema) a publié une analyse d’une faiblesse critique dans Microsoft Entra ID liée à des jetons internes dits _“actor tokens”_. Ces jetons, prévus à l’origine pour des usages internes/legacy, pouvaient être acceptés par certains endpoints anciens et permettre d’usurper n’importe quel utilisateur — y compris des Global Administrators — à travers des tenants différents. [dirkjanm.io+1](https://dirkjanm.io/obtaining-global-admin-in-every-entra-id-tenant-with-actor-tokens/?utm_source=chatgpt.com)

**Pourquoi c’est grave (impact technique)**  
Ces _actor tokens_ contournaient des mécanismes modernes de sécurité : ils pouvaient passer outre l’authentification multi-facteur (MFA) ou les policies de Conditional Access parce que la validation côté service était incomplète pour ces tokens legacy. De plus, leur usage laissait peu (ou pas) de traces normales dans certains journaux, rendant une compromission difficile à détecter. En pratique, cela pouvait permettre la création/suppression de comptes, réinitialisation de mots de passe, ou modification de configurations à l’échelle d’un tenant.

**Réponse & remédiation**  
Microsoft a été alerté en divulgation responsable, a assigné un CVE (CVE-2025-55241) et a déployé des correctifs/atténuations (blocage des acceptations de ces tokens legacy, patch des validations, retrait progressif des API legacy). Les recommandations pratiques sont : appliquer les correctifs Microsoft, auditer l’utilisation d’APIs legacy et d’applications enregistrées, bloquer les flows non utilisés (ex : Device Code Flow si non nécessaire), et renforcer la collecte de logs / alerting sur usages de tokens anormaux.

Anglais:
A security researcher discovered a critical problem in Microsoft Entra ID involving hidden “actor tokens.” These tokens were meant for old/internal services. Because old APIs accepted them, an attacker could pretend to be any user — even a Global Admin — across different tenants. [dirkjanm.io+1](https://dirkjanm.io/obtaining-global-admin-in-every-entra-id-tenant-with-actor-tokens/?utm_source=chatgpt.com)

**Why it’s dangerous (technical impact)**  
Actor tokens could bypass modern checks like MFA or Conditional Access. They also left very few normal logs, so a takeover could be both powerful and stealthy: create users, reset passwords, change settings — all without obvious traces.

**What Microsoft did**  
Microsoft was informed, assigned a CVE (CVE-2025-55241), and released fixes and mitigations. They are also phasing out legacy APIs and improving token validation. Organizations should patch, stop using legacy flows they don’t need, and improve logging. 

### Trend: Rise of Agentic AI and Automated Cybersecurity Operations

Security teams are increasingly using what is called “agentic AI” — meaning AI that does more than analyze threats; it can **take action** automatically within defined boundaries. [Axios](https://www.axios.com/2025/03/27/agentic-ai-cybersecurity-microsoft-crowdstrike?utm_source=chatgpt.com)  
**Why it matters**:

- With thousands of alerts per day, human teams can’t keep up. Automation helps speed the detection and response.
    
- But automatic agents bring risks: they may act wrongly if mis-configured, or attackers might exploit the automation.  
    **For a pentester or intern this means**:
    
- It’s no longer enough to know how to exploit a system; you must understand how automated defense systems might detect or respond.
    
- You could test a scenario where an automated agent isolates an endpoint — what happens if you trick or derail the agent?  
    **Short sentence to say in interview (EN)**:  
    “A major trend in 2025 is the use of autonomous AI agents in cybersecurity, which not only detect threats but act on them — reshaping SOC operations and creating new attack-and-defense dynamics.”

![[IMG-20251104014348788.png]]

![[IMG-20251104014403508.png]]

![[IMG-20251104014432520.png]]

![[IMG-20251104014511337.png]]

![[IMG-20251104014518487.png]]

![[IMG-20251104014526427.png]]

![[IMG-20251104014619864.png]]

**MDR** signifie **Managed Detection & Response**.![[IMG-20251104014817252.png]]

![[IMG-20251104014846517.png]]

![[IMG-20251104014857048.png]]

Hi, my name is Théophile, and I’m currently in my final year of engineering school at ECE Paris, where I specialize in cybersecurity.

I’m currently passionate about IT and network security. During my first year of engineering, I had the chance to study abroad at the Warsaw University of Technology in Poland. There, I focused on cryptography, C/C++ development, and security of information system.

Now, in my second year of the engineering cycle, I’m studying cybersecurity in depth — things like Linux and Windows security, Active Directory, forensics, and container security. I’m also learning about networks, DevOps, and databases.

This summer, I did an internship at a cybersecurity startup called P4S. They created a hardware device that protects networks like a firewall and cipher, but without changing the existing setup. My job was to perform penetration testing on their device, then develop a script to automate these tests and generate a full security report.

Before that, I also worked at a small company called CoreTechnologie. There, I helped refactor their C++ code and later returned for a short project where I connected a 3D printer to their system using a Raspberry Pi and a custom API.

In 2024, I also did an internship at Delaware Consulting, where I worked on integrating an AI assistant into their SAP development environment. That gave me a taste of consulting and teamwork in a larger company.

Outside of school, I practice cybersecurity with CTFs and platforms like Hack The Box and TryHackMe, and I’m part of the cybersecurity club at my school.

To sum up, I’m a curious and motivated person who loves technical challenges, but also likes working with people. I’d really like to bring both my technical skills and my enthusiasm to a company like yours.
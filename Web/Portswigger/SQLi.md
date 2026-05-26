![[IMG-20251129160903811.png]]

![[IMG-20251129162121586.png]]

![[IMG-20251129162149985.png]]


![[IMG-20251129162203579.png]]

![[IMG-20251129162436606.png]]

![[IMG-20251129162533836.png]]

![[IMG-20251129163113417.png]]

![[IMG-20251129163119950.png]]

![[IMG-20251129163138280.png]]

![[IMG-20251129163144218.png]]

![[IMG-20251129163206195.png]]

![[IMG-20251129163211917.png]]

![[IMG-20251129163241862.png]]

![[IMG-20251129163248024.png]]




### 🔴 Points notables

#### 1. **Validation côté client uniquement**

javascript

```javascript
yii.validation.required(...)
yii.validation.string(..., {"max":20, ...})
```

Toute la validation du formulaire (longueur, format, required) est faite **uniquement en JS**. Un attaquant peut bypass trivalement en envoyant la requête directement avec `curl`/Burp.

---

#### 2. **Endpoint sensible exposé en clair**

javascript

```javascript
url: '/login/forgotpassword',
```

Endpoint de reset de mot de passe direct, sans token CSRF visible dans le code (le `form.serialize()` peut l'inclure via Yii, mais ça mérite vérification).

---

#### 3. **Regex permissive sur le champ agent_code**

javascript

```javascript
/^[A-Za-z0-9 -.\/]+$/
```

Le `/` est autorisé → risque de **path traversal** si cette valeur est utilisée côté serveur dans un chemin de fichier ou une requête.

---

#### 4. **Framework fingerprinting trivial**

javascript

```javascript
yii.validation / yiiActiveForm
```

Le framework **Yii2** est clairement identifiable → permet de cibler des CVEs connues (ex: CVE-2024-4... selon la version).

---

#### 5. **Gestion d'erreur verbeuse**

javascript

```javascript
'ทำรายการไม่สำเร็จ' + ' เนื่องจาก' + data.description
```

Le `data.description` retourné par le serveur est affiché **directement dans le DOM** sans sanitisation → potentiel **XSS stocké/réfléchi** si le serveur renvoie une valeur contrôlable.

---

### ✅ Priorités de test

| Vecteur                    | Action                                                            |
| -------------------------- | ----------------------------------------------------------------- |
| Bypass validation          | Envoyer POST direct sur `/login/forgotpassword`                   |
| User enumeration           | Tester avec agents codes valides/invalides, comparer les réponses |
| XSS via `data.description` | Injecter `<img src=x onerror=alert(1)>` dans les champs           |
| CSRF                       | Vérifier si un token est bien inclus dans `form.serialize()`      |
| Path traversal             | Tester `../` dans `agent_code`                                    |
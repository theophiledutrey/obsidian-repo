[

# The Ultimate Guide to JWT Vulnerabilities and Attacks (with Exploitation Examples)

###### Published: **05 May 2025**

Share

JSON Web Tokens (JWTs) are widely used for authentication, authorization, and secure information exchange in modern web applications. They're often used in OAuth2 flows, stateless session handling, API access, and SSO implementations.

A JWT consists of three parts, separated by dots:

```css
HEADER.PAYLOAD.SIGNATURE
```

- **HEADER**: Defines the type of token and the signing algorithm (e.g. `HS256`).
- **PAYLOAD**: Contains claims about the user, session, or other data (e.g. `{"user": "user1", "admin": false}`).
- **SIGNATURE**: A cryptographic signature that ensures the token hasn't been tampered with.

Each part is Base64URL-encoded (without padding) and concatenated with a dot:

```undefined
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiJ1c2VyMSIsImFkbWluIjpmYWxzZX0.
X5cBA0klC0df_vxTqM-M1WOUbE8Qzj0Kh3w_N6Y7LkI
```

## 🧪 JSON Web Algorithms (JWA)

The JWT specification supports multiple algorithms, defined in the JWA (JSON Web Algorithms) specification:

- **Symmetric algorithms** (HMAC based using a shared secret): `HS256`, `HS384`, `HS512`
- **Asymmetric algorithms** (public/private key): `RS256` (RSA based), `ES256` (Elliptic Curve based), `PS256` (RSA based with MGF1 padding), etc.
- **None**: A non-algorithm that implies no signature (insecure and should never be used)

When a token is issued, it’s signed by the issuer using the specified algorithm. The recipient must verify the signature before trusting the payload.

The code to sign a token signs the concatenation of `header + "." + payload` based on the `ALGORITHM` picked by the developer:

```ini
signature = ALGORITHM.Sign(header + "." + payload, key)
```

In the same way the verification is done on `header + "." + payload`:

```vbnet
ALGORITHM.Verify(signature, header + "." + payload, key)
```

For the verification, there are multiple strategies developers can use to pick the `ALGORITHM`, they can hardcode it (safer) or use the value coming from the JWT header (attacker-controlled, not as safe).

## 🔄 One Website, Many JWT Implementations

In modern architectures, a single web application can be composed of dozens of microservices. Even if they share a hostname, each service may:

- Use a different JWT library
- Use a different signing key or verification logic
- Parse and validate tokens differently

**This means every endpoint must be tested individually.** Don’t assume that if the login or main API endpoint handles JWT securely, all others do too. A misconfigured service or third-party microservice might still be vulnerable.

Throughout this guide, we’ll cover the most common — and most dangerous — JWT implementation flaws, how they are exploited, and how to detect or defend against them. Each section links to **PentesterLab** exercises so you can practice the attacks in a hands-on environment.

---

## 🔓 1. Signature Not Verified

One of the most common and dangerous implementation mistakes when using JWTs is **failing to verify the signature**. JWTs are not encrypted — their purpose is to provide integrity. This means the contents of the token can be viewed by anyone, but _should not_ be trusted unless the signature has been verified.

Unfortunately, some applications skip this critical step. This often happens because developers use a library’s `decode()` method instead of `verify()`, or they temporarily disable signature verification during testing and forget to re-enable it.

### Exploitation

If a JWT is not verified before use, an attacker can forge arbitrary claims. The steps are trivial:

1. Obtain a valid token (e.g., by registering or logging in as a normal user).
2. Base64URL-decode the token to view the header and payload.
3. Modify the payload, for example changing:
    
    ```json
    {"user": "bob", "role": "user"}
    ```
    
    to:
    
    ```json
    {"user": "admin", "role": "admin"}
    ```
    
4. Base64URL-encode the modified header and payload.
5. Reassemble the token. You can:
    - Keep the original signature (most likely to work), or
    - Remove it completely and just send `header.payload.` (less likely to work)
6. Send the token in a request (e.g., as a cookie or `Authorization` header).

If the server does not verify the signature, it will treat the forged claims as valid — and you’ll be authenticated as `admin`.

Even experienced developers can make this mistake when trying to quickly inspect a token’s contents or during local testing.

### Impact

This issue can lead to:

- Authentication bypass
- Authorization bypass

This issue effectively renders JWT-based authentication useless if not properly handled.

### Mitigations

- Always use a library’s **verify()** method before accessing claims.
- Never trust the payload until the signature is successfully validated.
- Add integration tests that verify signature enforcement across all endpoints.
- Use code reviews and static analysis to detect misuse of `decode()` or insecure JWT flows.

### Practice It 🧪

You can try this exact attack in a hands-on lab:

**👉 [PentesterLab: JWT Without Signature Verification](https://pentesterlab.com/exercises/jwt-vii)**

---

## ❌ 2. None Algorithm Attack

The JWT specification allows tokens to specify the signing algorithm in their header using the `"alg"` field. Early versions of many JWT libraries accepted `None` or `none` as a valid option, meaning the token was considered valid **without a signature at all**. This was mostly due to developers of the library following the JWT specification and implementing all the required algorithms.

This was originally intended for debugging or unsecured flows, but in practice, it opened a serious security hole when libraries did not explicitly disable or reject the `none` algorithm.

### Exploitation

To exploit a JWT implementation that allows `"none"`:

1. Obtain a valid token (e.g., login as a normal user).
2. Base64URL-decode the JWT and modify the header:
    
    ```json
    {"alg": "HS256", "typ": "JWT"}
    ```
    
    becomes:
    
    ```json
    {"alg": "none", "typ": "JWT"}
    ```
    
    or
    
    ```json
    {"alg": "None", "typ": "JWT"}
    ```
    
3. Modify the payload to escalate privileges:
    
    ```json
    {"user": "admin"}
    ```
    
4. Base64URL-encode the new header and payload.
5. Assemble the token with an **empty signature part**:
    
    ```scss
    base64url(header) + "." + base64url(payload) + "."
    ```
    
6. Send the token to the application.

If the backend does not reject tokens with `"alg": "none"`, it will accept this token as valid — and you’re now `admin` without any cryptographic proof.

### Impact

This issue can lead to:

- Authentication bypass
- Authorization bypass

This issue effectively renders JWT-based authentication useless if not properly handled.

### Mitigations

- **Explicitly disable the "none" algorithm** in your JWT library configuration.
- Do not rely on defaults, enforce algorithm allowlists like `RS256` or `HS256`.
- Reject tokens that contain `"alg": "none"` at the parser level.
- Consider validating the algorithm independently from the token itself.

### Practice It 🧪

Try this vulnerability in a hands-on lab:

**👉 [PentesterLab: JWT None Algorithm](https://pentesterlab.com/exercises/jwt)**

## 🧂 3. Trivial Secret (Weak HMAC Keys)

When using HMAC-based algorithms like `HS256`, the integrity of the JWT depends entirely on the secrecy and strength of the shared secret key. If the key is weak, guessable, or hardcoded, an attacker can brute-force it using a known JWT and use it to forge arbitrary tokens.

This vulnerability can be common in poorly secured APIs and test environments, and it often affects production systems due to careless key management.

### Exploitation

The attacker needs just one valid token. With that, they can run an offline brute-force attack to recover the secret. Here's how:

1. Capture a valid JWT from the application.
2. Split it into the three parts: `header.payload.signature`.
3. Use a tool like [Hashcat](https://hashcat.net/hashcat/), or a custom script to brute-force the shared secret by computing:
    
    ```bash
    HMAC(secret, base64url(header) + "." + base64url(payload)) == signature
    ```
    
4. Once the secret is found, modify the payload (e.g., escalate role or spoof another user).
5. Re-sign the token using the cracked secret and send it to the application.

This entire attack can be performed offline, without generating noise or alerts on the target system.

Common weak secrets include:

- `"secret"`
- `"123456"`
- Service or project names (e.g., `"my-api"`)
- Hardcoded defaults in open-source projects

You can use a list of known JWT secrets like [wallarm/jwt-secrets](https://github.com/wallarm/jwt-secrets) to increase your chance of recovering the secret.

### Mitigation

- Use cryptographically strong secrets for HMAC algorithms (e.g., 32+ random bytes).
- Never hardcode secrets in source code or config files.
- Rotate secrets periodically and use environment-specific secrets.
- Support for multiple secrets to enable rotation.
- Log and monitor token validation errors.

### Practice It 🧪

Try this attack in a hands-on environment with a weak secret you can crack yourself:

**👉 [PentesterLab: JWT Trivial Secret](https://pentesterlab.com/exercises/jwt-v)**

---

## 🔀 4. Algorithm Confusion (RSA to HMAC)

One of the most subtle, yet devastating, JWT vulnerabilities arises from **algorithm confusion**. This attack exploits the fact that the JWT header includes a user-controlled `"alg"` parameter. If the server doesn’t enforce which algorithm is expected, an attacker can manipulate the header to cause the backend to verify the token using the wrong algorithm — often with catastrophic consequences.

The most common variant: swapping an `RS256` (RSA) token to `HS256` (HMAC), and then using the RSA public key (meant only for verification) as the HMAC **secret**.

### Exploitation

This attack works because of how asymmetric (RSA) and symmetric (HMAC) algorithms function:

- **RSA (RS256)**: The server signs with its private key and verifies with its public key.
- **HMAC (HS256)**: The same secret is used for both signing and verification.

If the server trusts the `"alg"` field from the token header and uses the public key as the HMAC secret, an attacker can:

1. Obtain a valid JWT signed with RSA.
2. Base64URL-decode the token and change the header from:
    
    ```json
    {"alg": "RS256", "typ": "JWT"}
    ```
    
    to:
    
    ```json
    {"alg": "HS256", "typ": "JWT"}
    ```
    
3. Modify the payload (e.g., change user role or identity).
4. Sign the new `header.payload` using **HMAC with the server’s RSA public key**.
5. Send the forged token.

If the server blindly uses `HS256` and its public key as the HMAC secret, the forged token will validate — and the attacker can fully impersonate any user.

### How to Get the Public Key

There are many ways to get access to the public key:

- Sometimes embedded in frontend JavaScript
- Hardcoded in mobile apps
- Published in documentation or well-known JWK endpoints
- Recovered from ECDSA signatures or multiple RSA signatures using tools such as [rsa_sign2n](https://github.com/silentsignal/rsa_sign2n)

### Impact

This issue can lead to:

- Authentication bypass
- Authorization bypass

### Mitigation

- **Never trust the "alg" field from the JWT itself**.
- Enforce the expected algorithm at the configuration level (e.g., `alg = RS256` only).
- Separate token parsing from verification logic — and never auto-select algorithms.
- Use libraries that do not allow dynamic algorithm switching or require explicit key types.

### Practice It 🧪

Try this exact attack by forging a token using the public key as the HMAC secret:

**👉 [PentesterLab: JWT Algorithm Confusion](https://pentesterlab.com/exercises/jwt-algorithm-confusion) and [PentesterLab: JWT Algorithm Confusion with RSA Public Key Recovery](https://pentesterlab.com/exercises/jwt-algorithm-confusion-rsa-key-recovery)**

## 🔀 4b. Algorithm Confusion (ECDSA to HMAC)

This variation of the algorithm confusion attack targets applications using **ECDSA (Elliptic Curve Digital Signature Algorithm)**, for example `ES256`. Just like the RSA-to-HMAC confusion, the core issue is that the application trusts the `"alg"` field from the JWT header, and uses it to select the verification method and key type dynamically.

By changing the `"alg"` field from `ES256` (ECDSA) to `HS256` (HMAC), an attacker can trick the server into verifying the token using an HMAC signature — and use the ECDSA public key as the HMAC secret.

### Exploitation

Here’s how the attack works:

1. Obtain a valid JWT signed using `ES256` (ECDSA).
2. Modify the token:
    - Change `"alg": "ES256"` to `"alg": "HS256"` in the header.
    - Modify the payload (e.g., set `"user": "admin"`).
    - Base64URL-encode the new header and payload.
3. Sign the `header.payload` using HMAC and the public ECDSA key as the secret.
4. Send the forged token to the server.

If the backend is vulnerable and uses the public key as a secret without validating the key type or the original algorithm, the forged HMAC will validate — and the attacker gains access with elevated privileges.

### Why This Works

ECDSA is asymmetric: it uses a private key to sign and a public key to verify.

HMAC is symmetric: it uses the same secret key to sign and verify.

If a system allows switching from ECDSA to HMAC, and treats the public key as a secret (because it’s all it has access to), it creates an unsafe equivalence between asymmetric and symmetric cryptography — and the attacker takes full advantage of this confusion.

### Recovering the Public Key

As with RSA, you can find the key in documentation, SDK or in mobile apps. Alternatively, you can programmatically recover two potential public keys from a signature. You can find more details and code to recover the ECDSA public keys in our blog: [Algorithm Confusion Attacks against JWT using ECDSA](https://pentesterlab.com/blog/exploring-algorithm-confusion-attacks-on-jwt-exploiting-ecdsa).

### Impact

This issue can lead to:

- Authentication bypass
- Authorization bypass

### Mitigation

- **Never trust the "alg" field in the JWT header**.
- Enforce algorithms server-side (e.g., `alg = ES256` only).
- Do not allow clients to specify algorithms dynamically.
- Use libraries that reject unknown or unsupported algorithm types.

### Practice It 🧪

Try this attack in a lab that walks you through recovering the ECDSA public key and forging a JWT using HMAC:

**👉 [PentesterLab: JWT Algorithm Confusion with ECDSA Public Key Recovery](https://pentesterlab.com/exercises/jwt-algorithm-confusion-ecdsa-key-recovery)**

## 🪤 5. `kid` Injection (Key ID Manipulation)

The JWT header supports a field called `"kid"` — short for **Key ID**. This field allows the token to indicate which key should be used to verify the signature. It is especially useful in systems with key rotation or multiple signing keys.

However, when applications dynamically fetch keys based on this field — especially from filesystems or databases — the `kid` value becomes a dangerous injection point. If the application uses it insecurely (e.g., directly concatenating it into a file path or SQL query), attackers can manipulate it to point to keys they control or leak internal secrets.

### Exploitation: Path Traversal

In file-based key lookups, the application might do something like:

```ini
key_path = "/keys/" + kid
public_key = readFile(key_path)
```

An attacker can supply a JWT with:

```json
"kid": "../../../../dev/null"
```

This results in:

```bash
/keys/../../../../dev/null → /dev/null
```

Since reading from `/dev/null` will return an empty string, an attacker can forge a token and sign it with an empty string.

### Exploitation: SQL Injection

If the application loads keys from a database using an unsafe query:

```vbnet
SELECT key FROM keys WHERE kid = ''
```

The attacker can supply:

```json
"kid": "zzzz' UNION SELECT '123' --"
```

This causes the application to fetch and use an attacker-supplied value (`123`), which will successfully verify forged JWTs signed with the matching private key.

### Impact

This issue can lead to:

- Authentication bypass
- Authorization bypass
- Remote command execution
- SQL Injection

### Mitigation

- Validate `kid` strictly — never allow user-controlled paths or queries.
- Use allowlists of valid `kid` values with fixed file or key mappings.
- Sanitize and canonicalize paths before use.
- Use parameterized queries if accessing a database.
- Log and monitor invalid or unexpected `kid` values.

### Practice It 🧪

Practice injecting a malicious `kid` to control key selection and forge tokens:

**👉 [PentesterLab: JWT kid Injection and Directory Traversal](https://pentesterlab.com/exercises/jwt-iii)**

**👉 [PentesterLab: JWT kid Injection and RCE](https://pentesterlab.com/exercises/jwt-iv)**

**👉 [PentesterLab: JWT kid Injection and SQL Injection](https://pentesterlab.com/exercises/jwt-vi)**

## 🧬 6. Embedded JWK (CVE-2018-0114)

JWTs can optionally include a **JWK** (JSON Web Key) directly inside the token header using the `jwk` parameter. This is intended to allow token issuers to specify the public key that should be used to verify the token — particularly useful in distributed systems or rotating key setups.

However, if the server accepts any public key supplied in the token without proper validation (such as checking the issuer, key origin, or intended usage), an attacker can embed _their own public key_ into the header and generate tokens that validate against it.

This vulnerability was publicly disclosed as **CVE-2018-0114** and affected the popular `PyJWT` library. It allowed attackers to bypass authentication by embedding their key and signing tokens with the matching private key.

### Exploitation

To exploit this vulnerability, the attacker:

1. Generates their own RSA key pair.
2. Creates a JWT with a forged payload (e.g., `"user": "admin"`).
3. Includes their public key in the header under the `jwk` field:
    
    ```json
    
    "jwk": {
      "kty": "RSA",
      "e": "AQAB",
      "n": "..."
    }
        
    ```
    
4. Signs the token using their private key.
5. Sends the token to the vulnerable service.

If the application naively uses the JWK from the token header, the attacker’s key is used to verify the token — making the forged token appear legitimate.

### Impact

This issue can lead to:

- Authentication bypass
- Authorization bypass

### Mitigation

- **Never accept keys from the token itself**.
- If using a JWK from the header, validate:
    - Its issuer
    - Its source (is it known/trusted?)
    - Its purpose (e.g., ensure `"use": "sig"` and not `"enc"`)
- Disable `jwk` header parsing unless explicitly needed.
- Upgrade any libraries affected by CVE-2018-0114.

### Practice It 🧪

Try forging a JWT using your own key and bypass verification using the embedded `jwk`:

**👉 [PentesterLab: CVE-2018-0114](https://pentesterlab.com/exercises/cve-2018-0114)**

## 🌐 7. JKU / X5U Header Abuse

JWT supports additional headers like `jku` (JWK Set URL) and `x5u` (X.509 certificate URL) that point to external URLs where public keys can be retrieved. These fields are designed to help recipients dynamically fetch verification keys, especially in distributed or federated systems.

However, if the application does not strictly control the source of these URLs, it opens the door for Server-Side Request Forgery and using an attacker-controlled key. An attacker can host their own key set or certificate and sign tokens with their private key, then instruct the server (via `jku` or `x5u`) to download and trust that key.

### Exploitation

To exploit this behavior, an attacker will:

1. Generate their own RSA key pair.
2. Host the public key on a server they control, either:
    - As a JWK set (for `jku`)
    - As an X.509 certificate (for `x5u`)
3. Create a JWT with:
    - `"alg": "RS256"`
    - `"jku": "https://attacker.com/jwks.json"` or `"x5u": "https://attacker.com/cert.pem"`
4. Sign the token using their private key.
5. Send the forged token to the target application.

If the server accepts the remote key without validation, it will trust the token — because it successfully verifies with the attacker’s hosted key.

**This attack can also be exploited by leveraging a file upload, header injection or open redirect**

### Impact

This issue can lead to:

- Authentication bypass
- Authorization bypass
- Server-Side Request Forgery

### Mitigation

- Do not trust keys from arbitrary `jku` or `x5u` URLs.
- Implement an explicit allowlist of trusted domains for JWK and cert loading.
- Validate that the key downloaded from the remote URL matches expected `kid` values.
- Log and alert on unexpected external JWK or cert URLs.
- Prefer local key storage unless dynamic remote keys are absolutely necessary.

### Practice It 🧪

Practice forging a token that the server will trust based on the `jku` or `x5u` field:

**👉 [PentesterLab: JWT JKU attacks](https://pentesterlab.com/exercises/jwt-viii)**

**👉 [PentesterLab: JWT JKU and File Upload](https://pentesterlab.com/exercises/jwt-ix)**

**👉 [PentesterLab: JWT JKU and Open Redirect](https://pentesterlab.com/exercises/jwt-x)**

**👉 [PentesterLab: JWT JKU and Header Injection](https://pentesterlab.com/exercises/jwt-xi)**

## 🧙 8. CVE-2022-21449 (Psychic Signature)

In 2022, a critical vulnerability was discovered in the Java JDK’s ECDSA signature verification implementation. This bug, now known as the **“Psychic Signature”** vulnerability — allowed attackers to bypass digital signature verification entirely by submitting an invalid signature where both values (`s` and `r`) are set to zero.

Tracked as **CVE-2022-21449**, this bug impacted applications that used Java’s `java.security.Signature` class to verify ECDSA-signed JWTs, especially when using algorithms like `ES256`.

### Exploitation

The core of the vulnerability is that the Java implementation incorrectly accepted the signature with `r=0` and `s=0` as valid, even though these values should never occur in legitimate ECDSA signatures.

To exploit the issue:

1. Generate any JWT with `"alg": "ES256"` and a forged payload (e.g., `"user": "admin"`).
2. Base64URL-encode the header and payload.
3. Append a forged signature consisting of r=0 and s=0: (Base64URL-encoded: `MAYCAQACAQA`)
4. Send the JWT to the target Java-based service.

If the backend uses a vulnerable version of Java and ECDSA verification, it will **accept the forged token as valid** — bypassing all authentication and allowing privilege escalation.

### Why This Happens

- ECDSA signatures are composed of two integers: `r` and `s`.
- Java’s signature verification logic failed to reject values when both `r = 0` and `s = 0`.
- Since these values were not checked properly, **any JWT could be “valid”** when signed with a zeroed signature.

### Impact

This issue can lead to:

- Authentication bypass
- Authorization bypass

### Mitigation

- Upgrade to a patched version of Java (JDK 17.0.3+, 11.0.15+, 8u331+, etc.).
- Avoid using ECDSA signatures if your cryptographic library is untrusted or poorly maintained.
- Reject tokens with suspicious or malformed signatures — especially all-zero signatures.
- Write test cases that attempt to validate known-invalid JWTs.

### Practice It 🧪

Practice crafting a forged JWT using a zeroed signature to bypass verification:

**👉 [PentesterLab: JWT Psychic Signature aka CVE-2022-21449](https://pentesterlab.com/exercises/cve-2022-21449)**

## 📚 Final Thoughts: Mastering JWT Security

JWTs are powerful tools for stateless authentication, but they come with a complex and subtle attack surface. As you've seen throughout this guide, the most devastating JWT vulnerabilities often stem from small misconfigurations, incorrect assumptions, or over-trusting user-controlled data.

And the danger is compounded in modern architectures: a single application might use JWTs in dozens of different places — APIs, microservices, SSO layers, mobile backends — all with potentially different libraries, configs, and logic.

**If you're auditing or pentesting an app:**

- Test every endpoint individually
- Check for discrepancies in JWT parsing and verification
- Don’t assume one secure implementation covers the entire system

**If you're a developer or security engineer:**

- Never trust JWT headers blindly (especially `alg`, `kid`, `jku`, `x5u`, and `jwk`)
- Use proven libraries and keep them up-to-date
- Enforce strict configuration and avoid dynamic behaviors unless absolutely necessary




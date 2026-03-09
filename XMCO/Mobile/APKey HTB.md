```
apktool d apkey.apk
```

![[IMG-20260309162630146.png]]


```
jadx-gui apkey.apk
```

![[IMG-20260309171542725.png]]

```java
com.example.apkey.MainActivity r5 = com.example.apkey.MainActivity.this
android.content.Context r5 = r5.getApplicationContext()

com.example.apkey.MainActivity r0 = com.example.apkey.MainActivity.this
c.b.a.b r1 = r0.e
c.b.a.g r0 = r0.f

java.lang.String r0 = c.b.a.g.a()
java.lang.String r0 = c.b.a.b.a(r0)

android.widget.Toast r5 = android.widget.Toast.makeText(r5, r0, r1)
```


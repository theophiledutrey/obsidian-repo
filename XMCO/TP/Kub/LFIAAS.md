![[IMG-20260629145303423.png]]

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin

```

```
/var/run/secrets/kubernetes.io/serviceaccount/token

eyJhbGciOiJSUzI1NiIsImtpZCI6InRFYXh5NlBxYkZCUHhKeUJ3aXktMGFjc3VDdWFsUzVYbFh3ZkF3UFI3SDAifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJya2UyIl0sImV4cCI6MTgxNDI3MjQ5MiwiaWF0IjoxNzgyNzM2NDkyLCJpc3MiOiJodHRwczovL2t1YmVybmV0ZXMuZGVmYXVsdC5zdmMuY2x1c3Rlci5sb2NhbCIsImp0aSI6IjM2OTU1OGQ2LWQxNTctNDA4NS1iNjZmLWJhNzJjYWQ0NDAzNyIsImt1YmVybmV0ZXMuaW8iOnsibmFtZXNwYWNlIjoic2VydmljZXMiLCJub2RlIjp7Im5hbWUiOiJ4bWt1Yi13b3JrZXIiLCJ1aWQiOiJjZjdjN2NhMy1lZmNiLTQxNGItYjRmMC0zNGQ2N2JjNzE2NjgifSwicG9kIjp7Im5hbWUiOiJsZmlhYXMtYmFjay1kZXBsb3ltZW50LTVjNmI1N2NmZjYtNXI2bDQiLCJ1aWQiOiJiNzFkZTAzNy0wNjQ4LTQ4YTgtYTQyZi01ZjJkMmFiZGU4YzMifSwic2VydmljZWFjY291bnQiOnsibmFtZSI6ImxmaWFhcyIsInVpZCI6IjkwOTRkNzFhLTJmNDItNGY0NC1hYWYyLWEyOGFjZjIxYjk0NCJ9LCJ3YXJuYWZ0ZXIiOjE3ODI3NDAwOTl9LCJuYmYiOjE3ODI3MzY0OTIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpzZXJ2aWNlczpsZmlhYXMifQ.R0hFDcX2z3QglreOI6yOzXhIFHhSbe88WQ8xrLgTRJyWuYg6tQ11jmeDdrZfhsJsE_D29mBkqGuOC_wpBYOnQVyJ7K1ETecKYJsmZQCV7B_RJbZhxSStjkZNmMRqF5kejIGiJyaJUN7B97_P7V4558jfuavyV_0v-mAH_GqIWw8MVKmZLppndgPI0SqUnk-LenEvnw_XfEPUmSgO88UQww4DXG_ZjyJPdl6boc-atprjn_Nx1NpTGeFCJ_AGrUM5UdxvPdnb-vrhk3gDIU74CKvkSHxA_N0_VRcjdQ6RFRDxCABX9DMdpfLrSP3kUqB98sa14Ybnq_msKF3nTuuxxQ
```

```bash
var/run/secrets/kubernetes.io/serviceaccount/namespace

services
```

```
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

-----BEGIN CERTIFICATE-----
MIIBeTCCAR+gAwIBAgIBADAKBggqhkjOPQQDAjAkMSIwIAYDVQQDDBlya2UyLXNl
cnZlci1jYUAxNzgyNzE5NDkyMB4XDTI2MDYyOTA2NTEzMloXDTM2MDYyNjA2NTEz
MlowJDEiMCAGA1UEAwwZcmtlMi1zZXJ2ZXItY2FAMTc4MjcxOTQ5MjBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABG6J74pcTxy8ovAiCFOR2ZhCdc0XmnlA0iZK5lz2
0yK7Hg2jTorbbccVsGw0g74NGd94Yb5TFgjf7Udc7nWIXxOjQjBAMA4GA1UdDwEB
/wQEAwICpDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR8gx4qqaSg2AXyyN6y
x6cF2ppM7TAKBggqhkjOPQQDAgNIADBFAiAqe1ma3hTlbM6ZQ4y7IKXJsOUJM8jP
Ubwtex5oN1jdQwIhAJF/5k2YiUxqTgZvzHG6FhntDAaeZG/VK6phIAdC3AOV
-----END CERTIFICATE-----
```

```
# Extract the token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Extract namespace and CA
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

```bash
curl -s --cacert "$CACERT" \                                                                       15:26 29/06/2026
  -H "Authorization: Bearer $TOKEN" \
  "https://13.37.251.78:6443/api/v1/namespaces/$NAMESPACE/secrets" | jq
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {},
  "status": "Failure",
  "message": "secrets is forbidden: User \"system:serviceaccount:services:lfiaas\" cannot list resource \"secrets\" in API group \"\" in the namespace \"services\"",
  "reason": "Forbidden",
  "details": {
    "kind": "secrets"
  },
  "code": 403
}
```

```bash
 kubectl --token="$TOKEN" \                                                                         16:08 29/06/2026
  --server=https://13.37.251.78:6443 \
  --certificate-authority="$CACERT" \
  auth can-i --list
Resources                                       Non-Resource URLs                      Resource Names   Verbs
selfsubjectreviews.authentication.k8s.io        []                                     []               [create]
selfsubjectaccessreviews.authorization.k8s.io   []                                     []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                     []               [create]
namespaces                                      []                                     []               [get list watch]
pods/log                                        []                                     []               [get list watch]
pods                                            []                                     []               [get list watch]
ingresses.networking.k8s.io                     []                                     []               [get list watch]
                                                [/.well-known/openid-configuration/]   []               [get]
                                                [/.well-known/openid-configuration]    []               [get]
                                                [/api/*]                               []               [get]
                                                [/api]                                 []               [get]
                                                [/apis/*]                              []               [get]
                                                [/apis]                                []               [get]
                                                [/healthz]                             []               [get]
                                                [/healthz]                             []               [get]
                                                [/livez]                               []               [get]
                                                [/livez]                               []               [get]
                                                [/openapi/*]                           []               [get]
                                                [/openapi]                             []               [get]
                                                [/openid/v1/jwks/]                     []               [get]
                                                [/openid/v1/jwks]                      []               [get]
                                                [/readyz]                              []               [get]
                                                [/readyz]                              []               [get]
                                                [/version/]                            []               [get]
                                                [/version/]                            []               [get]
                                                [/version]                             []               [get]
                                                [/version]                             []               [get]
```

```bash
kubectl --token="$TOKEN" \                                                                             16:08 29/06/2026
  --server=https://13.37.251.78:6443 \
  --certificate-authority="$CACERT" \
  get rolebindings -n $NAMESPACE
Error from server (Forbidden): rolebindings.rbac.authorization.k8s.io is forbidden: User "system:serviceaccount:services:lfiaas" cannot list resource "rolebindings" in API group "rbac.authorization.k8s.io" in the namespace "services"
```

```bash
kubectl --token="$TOKEN" \                                                                             16:09 29/06/2026
  --server=https://13.37.251.78:6443 \
  --certificate-authority="$CACERT" \
  get clusterrolebindings
Error from server (Forbidden): clusterrolebindings.rbac.authorization.k8s.io is forbidden: User "system:serviceaccount:services:lfiaas" cannot list resource "clusterrolebindings" in API group "rbac.authorization.k8s.io" at the cluster scope

```

```bash
kubectl get ingress --all-namespaces \                                                                 
  --server=https://13.37.251.78:6443 \
  --token="$TOKEN" \
  --certificate-authority="$CACERT"
NAMESPACE   NAME                           CLASS    HOSTS                            ADDRESS                            PORTS     AGE
devops      gitlabkub-kas                  nginx    kas.gitlab.xmlab                 10.2.42.86,10.2.42.91,10.2.42.92   80, 443   6h48m
devops      gitlabkub-minio                nginx    minio.gitlab.xmlab               10.2.42.86,10.2.42.91,10.2.42.92   80, 443   6h48m
devops      gitlabkub-registry             nginx    registry.gitlab.xmlab            10.2.42.86,10.2.42.91,10.2.42.92   80, 443   6h48m
devops      gitlabkub-webservice-default   nginx    gitlab.gitlab.xmlab              10.2.42.86,10.2.42.91,10.2.42.92   80, 443   6h48m
devops      harborkub-ingress              <none>   registry.xmlab                   10.2.42.86,10.2.42.91,10.2.42.92   80, 443   6h49m
secret      back-flagaas-ingress           <none>   flagaas-back.xmlab               10.2.42.86,10.2.42.91,10.2.42.92   80, 443   6h17m
secret      front-ingress                  <none>   flagaas.xmlab                    10.2.42.86,10.2.42.91,10.2.42.92   80, 443   6h17m
secret      runjob-back-ingress            <none>   runjob-back.xmlab                10.2.42.86,10.2.42.91,10.2.42.92   80, 443   6h17m
secret      runjob-front-ingress           <none>   runjob.xmlab                     10.2.42.86,10.2.42.91,10.2.42.92   80, 443   6h17m
secret      secret-flag                    <none>   secret-flag-getme-please.xmlab   10.2.42.86,10.2.42.91,10.2.42.92   80, 443   6h14m
services    back-ingress                   <none>   lfiaas-back.xmlab                10.2.42.86,10.2.42.91,10.2.42.92   80, 443   6h17m
services    back-ingress-rceaas            <none>   rceaas-back.xmlab                10.2.42.86,10.2.42.91,10.2.42.92   80, 443   6h17m
services    front-ingress                  <none>   lfiaas.xmlab                     10.2.42.86,10.2.42.91,10.2.42.92   80, 443   6h17m
services    front-ingress-rceaas           <none>   rceaas.xmlab                     10.2.42.86,10.2.42.91,10.2.42.92   80, 443   6h17m

```

```bash
~/Documents/XMCO/Labs/Kub/lfiaas
❯ kubectl get namespaces --all-namespaces \                                                                              17:18 29/06/2026
  --server=https://13.37.251.78:6443 \
  --token="$TOKEN" \
  --certificate-authority="$CACERT"
NAME              STATUS   AGE
cert-manager      Active   7h23m
default           Active   7h27m
devops            Active   7h24m
kube-node-lease   Active   7h27m
kube-public       Active   7h27m
kube-system       Active   7h27m
provision         Active   7h24m
secret            Active   7h24m
services          Active   7h24m

~/Documents/XMCO/Labs/Kub/lfiaas
❯ kubectl get pods --all-namespaces \                                                                                    17:19 29/06/2026
  --server=https://13.37.251.78:6443 \
  --token="$TOKEN" \
  --certificate-authority="$CACERT"
NAMESPACE      NAME                                                      READY   STATUS             RESTARTS        AGE
cert-manager   certmgrkub-cert-manager-5c66767cc7-bcz2d                  1/1     Running            0               7h23m
cert-manager   certmgrkub-cert-manager-cainjector-79765856b7-ncsxq       1/1     Running            0               7h23m
cert-manager   certmgrkub-cert-manager-webhook-6dc7757fd6-kl27g          1/1     Running            0               7h23m
default        flagsvc-deployment-c99b97796-vjfxb                        1/1     Running            0               6h43m
default        reflector-c68cbdf46-j6qdc                                 1/1     Running            0               7h22m
devops         gitlabkub-gitaly-0                                        1/1     Running            0               7h17m
devops         gitlabkub-gitlab-exporter-75c9976686-vzz8r                1/1     Running            0               7h17m
devops         gitlabkub-gitlab-runner-754dbb8489-ksl29                  1/1     Running            1 (7h15m ago)   7h17m
devops         gitlabkub-gitlab-shell-779f48dcf5-s4gg4                   1/1     Running            0               7h17m
devops         gitlabkub-gitlab-shell-779f48dcf5-t5dm7                   1/1     Running            0               7h17m
devops         gitlabkub-kas-6d64f8845b-lwvzx                            1/1     Running            0               7h17m
devops         gitlabkub-kas-6d64f8845b-vhx52                            1/1     Running            0               7h17m
devops         gitlabkub-migrations-1-4pcwb                              0/1     Completed          0               7h17m
devops         gitlabkub-minio-865ff4fbd5-8kk82                          1/1     Running            0               7h17m
devops         gitlabkub-minio-create-buckets-1-8jkcx                    0/1     Completed          0               7h17m
devops         gitlabkub-registry-fdfdbf77-kk44s                         1/1     Running            0               7h17m
devops         gitlabkub-registry-fdfdbf77-sgxcc                         1/1     Running            0               7h5m
devops         gitlabkub-sidekiq-all-in-1-v2-5d7fcc576-qzd6x             1/1     Running            0               7h17m
devops         gitlabkub-toolbox-dc94b4849-gvgmb                         1/1     Running            0               7h17m
devops         gitlabkub-webservice-default-cdddbb5f9-9vm29              2/2     Running            0               7h17m
devops         gitlabkub-webservice-default-cdddbb5f9-xbpbd              2/2     Running            0               7h17m
devops         harborkub-core-69bd5577fb-95bf4                           1/1     Running            0               7h18m
devops         harborkub-jobservice-5d5cbf54f8-fvrjt                     1/1     Running            2 (7h18m ago)   7h18m
devops         harborkub-portal-78f464b7cc-rqtzb                         1/1     Running            0               7h18m
devops         harborkub-registry-5bb8c8cf77-whv5h                       2/2     Running            0               7h18m
devops         pgsqlkub-postgresql-0                                     1/1     Running            0               7h24m
devops         rediskub-master-0                                         1/1     Running            0               7h23m
kube-system    cloud-controller-manager-xmkub-master                     1/1     Running            0               7h27m
kube-system    etcd-xmkub-master                                         1/1     Running            0               7h25m
kube-system    helm-install-rke2-canal-kv4rl                             0/1     Completed          0               7h27m
kube-system    helm-install-rke2-coredns-r4gm2                           0/1     Completed          0               7h27m
kube-system    helm-install-rke2-ingress-nginx-gwrh8                     0/1     Completed          0               7h27m
kube-system    helm-install-rke2-metrics-server-mnrzv                    0/1     Completed          2               7h27m
kube-system    helm-install-rke2-runtimeclasses-mxrws                    0/1     Completed          2               7h27m
kube-system    helm-install-rke2-snapshot-controller-crd-wlwvd           0/1     Completed          2               7h27m
kube-system    helm-install-rke2-snapshot-controller-z6bf5               0/1     Completed          0               7h27m
kube-system    kube-apiserver-xmkub-master                               1/1     Running            0               7h25m
kube-system    kube-controller-manager-xmkub-master                      1/1     Running            1 (7h25m ago)   7h27m
kube-system    kube-proxy-xmkub-master                                   1/1     Running            0               7h26m
kube-system    kube-proxy-xmkub-worker                                   1/1     Running            0               7h17m
kube-system    kube-proxy-xmkub-worker2                                  1/1     Running            0               7h17m
kube-system    kube-scheduler-xmkub-master                               1/1     Running            0               7h27m
kube-system    rke2-canal-9txrm                                          2/2     Running            0               7h26m
kube-system    rke2-canal-fhdcj                                          2/2     Running            0               7h26m
kube-system    rke2-canal-gczk9                                          2/2     Running            0               7h26m
kube-system    rke2-coredns-rke2-coredns-54c96855bc-bmn8f                1/1     Running            0               7h26m
kube-system    rke2-coredns-rke2-coredns-54c96855bc-n6d47                1/1     Running            0               7h25m
kube-system    rke2-coredns-rke2-coredns-autoscaler-785f6bc8fb-w7hp4     1/1     Running            0               7h26m
kube-system    rke2-ingress-nginx-controller-ffs7x                       1/1     Running            0               7h25m
kube-system    rke2-ingress-nginx-controller-qrd98                       1/1     Running            0               7h25m
kube-system    rke2-ingress-nginx-controller-vbhvj                       1/1     Running            0               7h25m
kube-system    rke2-metrics-server-6cf7c65cd8-tpcrk                      1/1     Running            0               7h25m
kube-system    rke2-snapshot-controller-85f96574d5-9xq4z                 1/1     Running            0               7h25m
provision      local-volume-provisioner-local-static-provisioner-nvrn5   1/1     Running            0               7h24m
provision      local-volume-provisioner-local-static-provisioner-scxxs   1/1     Running            0               7h24m
provision      local-volume-provisioner-local-static-provisioner-zxr84   1/1     Running            0               7h24m
secret         flag-deployment-96d444844-z2h56                           1/1     Running            0               6h43m
secret         flagaas-back-deployment-587644db57-vqc5r                  1/1     Running            0               6h46m
secret         flagaas-back-deployment-587644db57-zqncj                  1/1     Running            0               6h46m
secret         flagaas-front-deployment-6cd95b469c-52ngt                 1/1     Running            0               6h46m
secret         runjob-back-deployment-759f8d5b59-vfqcp                   0/1     ImagePullBackOff   0               6h46m
secret         runjob-back-deployment-797f5bccd5-c7x74                   0/1     ImagePullBackOff   0               6h46m
secret         runjob-front-deployment-56cdb6f566-mqgpk                  1/1     Running            0               6h46m
secret         runjob-front-deployment-6d6f4d4cd5-nn88f                  0/1     ImagePullBackOff   0               6h46m
services       lfiaas-back-deployment-5c6b57cff6-5r6l4                   1/1     Running            0               6h46m
services       lfiaas-front-deployment-548f844f8d-dqfd9                  1/1     Running            0               6h46m
services       rceaas-back-deployment-67989c4489-6hqq9                   1/1     Running            0               6h46m
services       rceaas-back-deployment-67989c4489-wsndm                   1/1     Running            0               6h46m
services       rceaas-back-deployment-84664c6c8-crmgb                    0/1     ImagePullBackOff   0               6h46m
services       rceaas-back-deployment-84664c6c8-p5tlk                    1/1     Running            0               6h46m
services       rceaas-front-deployment-688fffd48d-tthjz                  1/1     Running            0               6h46m
services       rceaas-front-deployment-dbd548546-nk8kk                   0/1     ImagePullBackOff   0               6h46m
```
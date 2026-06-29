
```
/var/run/secrets/kubernetes.io/serviceaccount/token

eyJhbGciOiJSUzI1NiIsImtpZCI6InRFYXh5NlBxYkZCUHhKeUJ3aXktMGFjc3VDdWFsUzVYbFh3ZkF3UFI3SDAifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJya2UyIl0sImV4cCI6MTgxNDI3NTM2MiwiaWF0IjoxNzgyNzM5MzYyLCJpc3MiOiJodHRwczovL2t1YmVybmV0ZXMuZGVmYXVsdC5zdmMuY2x1c3Rlci5sb2NhbCIsImp0aSI6IjVhNjRhN2M2LTMyZTAtNGNmZC04OGI3LTY1NmZlNTcyNmE4OCIsImt1YmVybmV0ZXMuaW8iOnsibmFtZXNwYWNlIjoic2VydmljZXMiLCJub2RlIjp7Im5hbWUiOiJ4bWt1Yi13b3JrZXIiLCJ1aWQiOiJjZjdjN2NhMy1lZmNiLTQxNGItYjRmMC0zNGQ2N2JjNzE2NjgifSwicG9kIjp7Im5hbWUiOiJyY2VhYXMtYmFjay1kZXBsb3ltZW50LTg0NjY0YzZjOC1wNXRsayIsInVpZCI6IjgzZGI2MGE0LTE3NmQtNDk2Ni1hMjA1LTAxMzBmYWQyNzk2ZSJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoicmNlYWFzIiwidWlkIjoiMTg3OWZiMTQtYTVmYi00MGRmLWExNGItOWEwNjliZDY3NGEwIn0sIndhcm5hZnRlciI6MTc4Mjc0Mjk2OX0sIm5iZiI6MTc4MjczOTM2Miwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OnNlcnZpY2VzOnJjZWFhcyJ9.TmyRxb3X2qCZ_kvYyMmueBQYCMiOxijul6fWKN2mKiefKwBUGxk53AYKImY9BGVWjeliH20BV8YkV7OMKdCEzj6QhZHf_YU3Dq6T7O17n-d4GpIFQC67rKktAu0TMPS-CpG3VRD-pDXXo0O1IKwWRD9MmaQ0xP-IWjBkJfDSgBfxJwu3ECSI7mUuqSSBLTzIat4Qhvtp4WbGzgVI4hqAWd9xczu5m6lXdICN7nRHmZHgw_3eZpm3pB9JbLbJ6X0zmUUQCmskqIHPCZJ8fqDT47YTuFbm3WEXLZz4FtFBXZLODoQDu00KCXssmqa-bYPnN0-D5jVneR-YkxTxsUC0OQ
```

```bash
/var/run/secrets/kubernetes.io/serviceaccount/namespace

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

```bash
kubectl --token="$TOKEN" \                                                                         16:04 29/06/2026
  --server=https://13.37.251.78:6443 \
  --certificate-authority="$CACERT" \
  auth can-i --list
  
Resources                                       Non-Resource URLs                      Resource Names   Verbs
selfsubjectreviews.authentication.k8s.io        []                                     []               [create]
selfsubjectaccessreviews.authorization.k8s.io   []                                     []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                     []               [create]
configmaps                                      []                                     []               [get list]
services                                        []                                     []               [get list]
clusterrolebindings.rbac.authorization.k8s.io   []                                     []               [get list]
clusterroles.rbac.authorization.k8s.io          []                                     []               [get list]
rolebindings.rbac.authorization.k8s.io          []                                     []               [get list]
roles.rbac.authorization.k8s.io                 []                                     []               [get list]
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
kubectl --token="$TOKEN" \                                                                         16:05 29/06/2026
  --server=https://13.37.251.78:6443 \
  --certificate-authority="$CACERT" \
  get rolebindings -n $NAMESPACE
NAME                ROLE                AGE
admin-ns-services   ClusterRole/admin   6h3m
```

```bash
kubectl --token="$TOKEN" \                                                                         16:05 29/06/2026
  --server=https://13.37.251.78:6443 \
  --certificate-authority="$CACERT" \
  get clusterrolebindings
NAME                                                             ROLE                                                                             AGE
canal-calico                                                     ClusterRole/calico-node                                                          6h13m
canal-flannel                                                    ClusterRole/flannel                                                              6h13m
certmgrkub-cert-manager-cainjector                               ClusterRole/certmgrkub-cert-manager-cainjector                                   6h9m
certmgrkub-cert-manager-controller-approve:cert-manager-io       ClusterRole/certmgrkub-cert-manager-controller-approve:cert-manager-io           6h9m
certmgrkub-cert-manager-controller-certificates                  ClusterRole/certmgrkub-cert-manager-controller-certificates                      6h9m
certmgrkub-cert-manager-controller-certificatesigningrequests    ClusterRole/certmgrkub-cert-manager-controller-certificatesigningrequests        6h9m
certmgrkub-cert-manager-controller-challenges                    ClusterRole/certmgrkub-cert-manager-controller-challenges                        6h9m
certmgrkub-cert-manager-controller-clusterissuers                ClusterRole/certmgrkub-cert-manager-controller-clusterissuers                    6h9m
certmgrkub-cert-manager-controller-ingress-shim                  ClusterRole/certmgrkub-cert-manager-controller-ingress-shim                      6h9m
certmgrkub-cert-manager-controller-issuers                       ClusterRole/certmgrkub-cert-manager-controller-issuers                           6h9m
certmgrkub-cert-manager-controller-orders                        ClusterRole/certmgrkub-cert-manager-controller-orders                            6h9m
certmgrkub-cert-manager-webhook:subjectaccessreviews             ClusterRole/certmgrkub-cert-manager-webhook:subjectaccessreviews                 6h9m
cluster-admin                                                    ClusterRole/cluster-admin                                                        6h13m
helm-kube-system-rke2-canal                                      ClusterRole/cluster-admin                                                        6h13m
helm-kube-system-rke2-coredns                                    ClusterRole/cluster-admin                                                        6h13m
helm-kube-system-rke2-ingress-nginx                              ClusterRole/cluster-admin                                                        6h13m
helm-kube-system-rke2-metrics-server                             ClusterRole/cluster-admin                                                        6h13m
helm-kube-system-rke2-runtimeclasses                             ClusterRole/cluster-admin                                                        6h13m
helm-kube-system-rke2-snapshot-controller                        ClusterRole/cluster-admin                                                        6h13m
helm-kube-system-rke2-snapshot-controller-crd                    ClusterRole/cluster-admin                                                        6h13m
kube-apiserver-kubelet-admin                                     ClusterRole/system:kubelet-api-admin                                             6h13m
local-volume-provisioner-local-static-provisioner-node-binding   ClusterRole/local-volume-provisioner-local-static-provisioner-node-clusterrole   6h11m
read-ns-pods-ing                                                 ClusterRole/read-ns-pods-ing                                                     6h3m
read-svc-r-rb-cr-crb-cm                                          ClusterRole/read-svc-r-rb-cr-crb-cm                                              6h3m
reflector                                                        ClusterRole/reflector                                                            6h9m
rke2-cloud-controller-manager                                    ClusterRole/rke2-cloud-controller-manager                                        6h13m
rke2-cloud-controller-manager-auth-delegator                     ClusterRole/system:auth-delegator                                                6h13m
rke2-coredns-rke2-coredns                                        ClusterRole/rke2-coredns-rke2-coredns                                            6h13m
rke2-coredns-rke2-coredns-autoscaler                             ClusterRole/rke2-coredns-rke2-coredns-autoscaler                                 6h13m
rke2-ingress-nginx                                               ClusterRole/rke2-ingress-nginx                                                   6h11m
rke2-metrics-server:system:auth-delegator                        ClusterRole/system:auth-delegator                                                6h12m
rke2-snapshot-controller                                         ClusterRole/rke2-snapshot-controller                                             6h12m
system:basic-user                                                ClusterRole/system:basic-user                                                    6h13m
system:controller:attachdetach-controller                        ClusterRole/system:controller:attachdetach-controller                            6h13m
system:controller:certificate-controller                         ClusterRole/system:controller:certificate-controller                             6h13m
system:controller:clusterrole-aggregation-controller             ClusterRole/system:controller:clusterrole-aggregation-controller                 6h13m
system:controller:cronjob-controller                             ClusterRole/system:controller:cronjob-controller                                 6h13m
system:controller:daemon-set-controller                          ClusterRole/system:controller:daemon-set-controller                              6h13m
system:controller:deployment-controller                          ClusterRole/system:controller:deployment-controller                              6h13m
system:controller:disruption-controller                          ClusterRole/system:controller:disruption-controller                              6h13m
system:controller:endpoint-controller                            ClusterRole/system:controller:endpoint-controller                                6h13m
system:controller:endpointslice-controller                       ClusterRole/system:controller:endpointslice-controller                           6h13m
system:controller:endpointslicemirroring-controller              ClusterRole/system:controller:endpointslicemirroring-controller                  6h13m
system:controller:ephemeral-volume-controller                    ClusterRole/system:controller:ephemeral-volume-controller                        6h13m
system:controller:expand-controller                              ClusterRole/system:controller:expand-controller                                  6h13m
system:controller:generic-garbage-collector                      ClusterRole/system:controller:generic-garbage-collector                          6h13m
system:controller:horizontal-pod-autoscaler                      ClusterRole/system:controller:horizontal-pod-autoscaler                          6h13m
system:controller:job-controller                                 ClusterRole/system:controller:job-controller                                     6h13m
system:controller:legacy-service-account-token-cleaner           ClusterRole/system:controller:legacy-service-account-token-cleaner               6h13m
system:controller:namespace-controller                           ClusterRole/system:controller:namespace-controller                               6h13m
system:controller:node-controller                                ClusterRole/system:controller:node-controller                                    6h13m
system:controller:persistent-volume-binder                       ClusterRole/system:controller:persistent-volume-binder                           6h13m
system:controller:pod-garbage-collector                          ClusterRole/system:controller:pod-garbage-collector                              6h13m
system:controller:pv-protection-controller                       ClusterRole/system:controller:pv-protection-controller                           6h13m
system:controller:pvc-protection-controller                      ClusterRole/system:controller:pvc-protection-controller                          6h13m
system:controller:replicaset-controller                          ClusterRole/system:controller:replicaset-controller                              6h13m
system:controller:replication-controller                         ClusterRole/system:controller:replication-controller                             6h13m
system:controller:resource-claim-controller                      ClusterRole/system:controller:resource-claim-controller                          6h13m
system:controller:resourcequota-controller                       ClusterRole/system:controller:resourcequota-controller                           6h13m
system:controller:root-ca-cert-publisher                         ClusterRole/system:controller:root-ca-cert-publisher                             6h13m
system:controller:route-controller                               ClusterRole/system:controller:route-controller                                   6h13m
system:controller:selinux-warning-controller                     ClusterRole/system:controller:selinux-warning-controller                         6h13m
system:controller:service-account-controller                     ClusterRole/system:controller:service-account-controller                         6h13m
system:controller:service-cidrs-controller                       ClusterRole/system:controller:service-cidrs-controller                           6h13m
system:controller:service-controller                             ClusterRole/system:controller:service-controller                                 6h13m
system:controller:statefulset-controller                         ClusterRole/system:controller:statefulset-controller                             6h13m
system:controller:ttl-after-finished-controller                  ClusterRole/system:controller:ttl-after-finished-controller                      6h13m
system:controller:ttl-controller                                 ClusterRole/system:controller:ttl-controller                                     6h13m
system:controller:validatingadmissionpolicy-status-controller    ClusterRole/system:controller:validatingadmissionpolicy-status-controller        6h13m
system:controller:volumeattributesclass-protection-controller    ClusterRole/system:controller:volumeattributesclass-protection-controller        6h13m
system:discovery                                                 ClusterRole/system:discovery                                                     6h13m
system:kube-controller-manager                                   ClusterRole/system:kube-controller-manager                                       6h13m
system:kube-dns                                                  ClusterRole/system:kube-dns                                                      6h13m
system:kube-proxy                                                ClusterRole/system:kube-proxy                                                    6h13m
system:kube-scheduler                                            ClusterRole/system:kube-scheduler                                                6h13m
system:monitoring                                                ClusterRole/system:monitoring                                                    6h13m
system:node                                                      ClusterRole/system:node                                                          6h13m
system:node-proxier                                              ClusterRole/system:node-proxier                                                  6h13m
system:public-info-viewer                                        ClusterRole/system:public-info-viewer                                            6h13m
system:rke2-controller                                           ClusterRole/system:rke2-controller                                               6h13m
system:rke2-metrics-server                                       ClusterRole/system:rke2-metrics-server                                           6h12m
system:service-account-issuer-discovery                          ClusterRole/system:service-account-issuer-discovery                              6h13m
system:volume-scheduler                                          ClusterRole/system:volume-scheduler

```


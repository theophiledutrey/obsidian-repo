```
XMKUB{somel3eaksetcpasswdyoule4k3dtheflag}

XMKUB{--n0tthem0stdifficult0ne--}

XMKUB{FlemmeDeMettreDansLeVaultDeTouteFaconCeCredentialsNeSertQuaAppelerUneAPIMoisie}
```

```
flagaas=> SELECT * FROM baseschema.flag;
 id |     name     |                 description                 | indice |                        hashed_flag_secret                        |       creation_date        |        last_flagged        | last_flagged_by
----+--------------+---------------------------------------------+--------+------------------------------------------------------------------+----------------------------+----------------------------+-----------------
  3 | SQLI?        | Somewhere in a database                     |        | 18eed05d7fe6127dc5a78ed06812dcc1cf9512dbaa7bf98fd4d5eac3fee0e1f3 | 2026-06-29 08:36:38.480045 |                            |
  5 | Redrum       | Search something red                        |        | 5e6d7ce4845e7fc1044bf7e315c0591ce3183ab4465edcc303c18f3a54c05dd7 | 2026-06-29 08:36:40.869388 |                            |
  6 | Git          | Gitlab is often the core                    |        | 7af171c5299ecdbb89f4b7aa324c47f7e6b924026a1d81bc4bdc44e82e9b006c | 2026-06-29 08:36:42.05408  |                            |
 10 | Harbor       | Somewhere in the Harbor                     |        | 2b972b2cdab901d720473445117493543b5adc002ea8377e8e29211362f67df1 | 2026-06-29 08:36:46.864756 |                            |
  2 | RCE?         | RCE ...                                     |        | f42d8b6a572878cf23ec5dc27fc3ffeedbe8fe69fa2f191a9d60ee60c0e8811b | 2026-06-29 08:36:37.280363 | 2026-06-29 15:29:48.543978 | Theophile
 11 | Configmapped | Can you read what you access?               |        | 9692e58c7b2b6adfabfc55f0fe354ed6b71ef998c50792d7c1f7b37d8603b4fb | 2026-06-29 08:36:48.109474 | 2026-06-30 09:22:22.400534 | Theophile
  4 | Secret       | Somewhere ...                               |        | 17ded38f78fe929263d288889c9adc643f929c7db3b796f508d47619fff0e2d3 | 2026-06-29 08:36:39.671116 | 2026-06-30 10:02:39.363472 | Theophile
  8 | Worker adm   | Escalate root on workers                    |        | 37aae64e87d43d964624c027dd07a8570b8073ba27857293af7ce148d16c7cbc | 2026-06-29 08:36:44.404573 | 2026-07-01 09:03:18.469858 | Theophile
  7 | Cluster adm  | When you will be cluster admin              |        | d8c4f513f1306edb83442e4a24c63c90490ad7985593ff29fed59e506469839e | 2026-06-29 08:36:43.233747 | 2026-07-01 09:42:10.819032 | Theophile
  1 | LFI?         | LFI maybe                                   |        | c9317465d6a5c213fa16a57a77bc9c17b7732ccd19e7d8d08893e88e5f5e5fe3 | 2026-06-29 08:36:36.034589 | 2026-07-01 12:58:52.274387 | Theophile
 12 | Internal     | Maybe some internal services can be reached |        | d4ff6222ff7d38c5af36abadd5336b11c26a6a5a5631646a4d90a9e4c333609c | 2026-06-29 08:36:49.347931 | 2026-07-01 12:59:35.373139 | Theophile
  9 | Master adm   | Escalate root on the master                 |        | 965cbfbfa08e954c42e8b9205a84afc94228df5b321a7fbef5d7f9997e387880 | 2026-06-29 08:36:45.58093  | 2026-07-02 12:33:25.126656 | Theophile
(12 rows)
```

![[IMG-20260702173823716.png]]


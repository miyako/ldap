# LDAP_SET_OPTIONS

`LDAP_SET_OPTIONS(options : Object)`

Not in the built-in theme. Sets connection options for the next
[LDAP_LOGIN](LDAP_LOGIN.md) in the current process. Accepts every
[cs.ldap.LDAP](../Classes/LDAP.md#constructor) connection property except
`password`. Pass `Null` to clear.

```4d
LDAP_SET_OPTIONS({caCert: $internalRootPEM; operationTimeout: 30; binary: "decode"})
LDAP_LOGIN("ldaps://dc1.corp.example"; "CORP\\svc-4d"; $password)

LDAP_SET_OPTIONS({domain: "corp.example"; mech: "gssapi"})  // Kerberos SSO
LDAP_LOGIN(""; ""; "")
```

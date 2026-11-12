# LDAP_SET_OPTIONS

`LDAP_SET_OPTIONS(options : Object)`

Not in the built-in theme. Sets connection options for the next
[LDAP_LOGIN](LDAP_LOGIN.md) in the current process. Accepts every
[cs.ldap.LDAP](../Classes/LDAP.md#constructor) connection property except
`password`. Pass `Null` to clear.

```4d
LDAP_SET_OPTIONS({caCert: $internalRootPEM; operationTimeout: 30; binary: "decode"})
LDAP_LOGIN("ldaps://dc1.corp.example"; "CORP\\svc-4d"; $password)

// Supplied application-user password, without changing LDAP_LOGIN's arguments:
LDAP_SET_OPTIONS({authMode: "explicit"; mech: "gssapi"; channelBinding: "require"})
LDAP_LOGIN("ldaps://dc1.corp.example"; "jdoe@CORP.EXAMPLE"; $password)

LDAP_SET_OPTIONS({domain: "corp.example"; authMode: "sso"; mech: "gssapi"})
LDAP_LOGIN(""; ""; "")
```

`authMode: "explicit"` defaults to `gssapi` and required CBT. Missing credentials
fail at login; they never select SSO or anonymous bind. `authMode: "sso"` requires
empty login/password. With no mode or SASL options, the simple-bind compatibility
default is unchanged. Options affect only the next login in this process, not
an existing session or another process.

The pinned CLI v0.1.0 cannot satisfy explicit/required-CBT mode. The component
fails closed until a genuine supporting CLI release is integrated; see
[authentication modes](../../../../docs/migration.md#authentication-modes).

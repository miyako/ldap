# LDAP_Session

`LDAP_Session() : cs.ldap.LDAP`

Not in the built-in theme. Returns the [cs.ldap.LDAP](../Classes/LDAP.md)
instance opened by [LDAP_LOGIN](LDAP_LOGIN.md) in the current process, or
`Null`. Migrated code can keep its login and legacy searches while new code uses
the full API on the same session:

```4d
LDAP_LOGIN($url; $login; $password)
$entry:=LDAP_Search($base; "(uid=jdoe)"; LDAP all levels)  // legacy call, unchanged apart from the name
$result:=LDAP_Session().modify($entry.dn; {replace: {mail: $mail}})  // writes were not possible before
```

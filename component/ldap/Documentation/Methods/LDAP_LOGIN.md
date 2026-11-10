# LDAP_LOGIN

`LDAP_LOGIN(url : Text; login : Text; password : Text {; digest : Integer})`

Drop-in replacement for the built-in `LDAP LOGIN`. Binds immediately (bad
credentials raise an error here) and keeps the session for the current process.

* `ldap://` is upgraded with StartTLS, and the password is only ever sent inside TLS.
* `digest` is accepted and ignored: DIGEST-MD5 is obsolete (RFC 6331); both values
  perform a simple bind inside TLS. On Active Directory use `DOMAIN\user`,
  `user@domain` or a DN as `login` (a bare sAMAccountName needs DIGEST-MD5).
* An empty `password` performs an anonymous bind.
* An empty `url` locates a domain controller through DNS; set the domain first
  with [LDAP_SET_OPTIONS](LDAP_SET_OPTIONS.md).
* With `LDAP_SET_OPTIONS({mech: "gssapi"; …})`, call `LDAP_LOGIN($url; ""; "")`
  for Kerberos single sign-on without any password.

Errors are raised with `componentSignature` `"ldap"`; see [Migration](../../../../docs/migration.md#errors).

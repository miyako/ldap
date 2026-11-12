# LDAP_LOGIN

`LDAP_LOGIN(url : Text; login : Text; password : Text {; digest : Integer})`

Drop-in replacement for the built-in `LDAP LOGIN`. Binds immediately (bad
credentials raise an error here) and keeps the session for the current process.

* `ldap://` is upgraded with StartTLS, and the password is only ever sent inside TLS.
* `digest` is accepted and ignored: DIGEST-MD5 is obsolete (RFC 6331); both values
  follow the authentication mode configured with `LDAP_SET_OPTIONS`. The
  compatibility default is simple bind inside TLS. On Active Directory use `DOMAIN\user`,
  `user@domain` or a DN as `login` (a bare sAMAccountName needs DIGEST-MD5).
* In compatibility simple-bind mode, an empty `password` performs an anonymous bind.
* An empty `url` locates a domain controller through DNS; set the domain first
  with [LDAP_SET_OPTIONS](LDAP_SET_OPTIONS.md).
* For supplied-user authentication against CBT-required AD, configure
  `LDAP_SET_OPTIONS({authMode: "explicit"; mech: "gssapi"; channelBinding: "require"})`
  once per process, then keep the existing `LDAP_LOGIN($url; $login; $password)`
  call. `login` must be a UPN (`user@CORP.EXAMPLE`), not a DN or `DOMAIN\user`.
  The supplied identity maps to `--user`, the password to stdin, and the
  configured SASL mechanism is **not** replaced with simple bind.
* Missing login/password in explicit mode raises error 49, never anonymous or
  service-account SSO. A failed login clears the previous process session.
* For intentional SSO, use `LDAP_SET_OPTIONS({authMode: "sso"; mech: "gssapi"; …})`
  and `LDAP_LOGIN($url; ""; "")`. Nonempty credentials in this mode raise error
  89. Legacy `mech: "gssapi"` without credentials or required CBT remains SSO.

Explicit mode defaults omitted `mech` / `channelBinding` to `gssapi` / `require`.
Required CBT without `authMode: "sso"`, or a configured non-simple mechanism
with a password, also selects explicit mode; incompatible settings fail rather
than downgrade. Strict login checks an authenticated, unpaged RootDSE search
before saving the session; it does not depend on the optional Who Am I operation.

The bundled CLI v0.2.0 implements this strict contract, including explicit
password GSSAPI without preexisting tickets. Each strict operation still checks
offline capabilities without a password; unsupported dependencies fail with
local error -1 before credential transmission. Transport/TLS failures raise 81;
authentication failures raise 49 with native diagnostics, not an invented CBT
diagnosis. Real AD Always-policy and Windows directory-authentication acceptance
remain outstanding; see [Migration](../../../../docs/migration.md#authentication-modes).

Errors are raised with `componentSignature` `"ldap"`. Catch them with
`ON ERR CALL(…; ek errors from components)`: a local handler does not see
component errors. See [Migration](../../../../docs/migration.md#errors).

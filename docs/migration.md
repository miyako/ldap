# Migrating from the built-in LDAP commands

The component ships one shared method per built-in command. Most code migrates
with a search and replace; the differences below are deliberate and make the
connection safer.

## 1. Rename the calls

| Built-in | Component | Call-site change |
|---|---|---|
| `LDAP LOGIN(url; login; password{; digest})` | `LDAP_LOGIN` | name only |
| `LDAP LOGOUT` | `LDAP_LOGOUT` | name only |
| `LDAP Search(dn; filter{; scope{; attrs{; asArray}}})` | `LDAP_Search` | arrays become pointers: `->attrs`, `->asArray` |
| `LDAP SEARCH ALL(dn; result; filter{; …})` | `LDAP_SEARCH_ALL` | `->result`, `->attrs`, `->asArray` |

Shared component methods cannot receive arrays directly, so array arguments
are passed as pointers. Collections are accepted too. The `LDAP root only`,
`LDAP root and next`, `LDAP all levels`, `LDAP password MD5` and
`LDAP password plain text` constants keep working.

```4d
// before
ARRAY TEXT($attrs; 0)
APPEND TO ARRAY($attrs; "mail")
LDAP LOGIN("ldap://dc1.corp.example"; "CORP\\jdoe"; $password; LDAP password plain text)
LDAP SEARCH ALL("DC=corp,DC=example"; $_entry; "(objectClass=user)"; LDAP all levels; $attrs)
LDAP LOGOUT

// after
LDAP_LOGIN("ldap://dc1.corp.example"; "CORP\\jdoe"; $password; LDAP password plain text)
LDAP_SEARCH_ALL("DC=corp,DC=example"; ->$_entry; "(objectClass=user)"; LDAP all levels; ->$attrs)
LDAP_LOGOUT
```

## 2. Behaviour that changes on purpose

| Topic | Built-in | Component | What to do |
|---|---|---|---|
| `ldap://` URLs | Plaintext connection | Upgraded with **StartTLS**; a password is never sent unencrypted | Nothing, if the server offers StartTLS (AD and OpenLDAP do). Otherwise use `ldaps://` |
| `digest` = MD5 (the default) | DIGEST-MD5 SASL bind | Simple bind **inside TLS**. DIGEST-MD5 is obsolete (RFC 6331) and incompatible with AD's LDAP channel binding | On AD, log in as `CORP\user`, `user@corp.example` or a DN. A bare sAMAccountName only worked with DIGEST-MD5 |
| `digest` = plain text | Password in clear on `ldap://` | Same simple bind, always encrypted | Nothing |
| Certificate checks | Depends on the platform library | Always verified against the OS trust store, with hostname verification | Internal CA not deployed on the machine: `LDAP_SET_OPTIONS({caCert: $pem})` |
| Empty `url` | Default server of the domain | DNS SRV discovery of the domain set with `LDAP_SET_OPTIONS({domain: …})` | Set the domain |
| Empty `password` | Anonymous bind | Anonymous bind (explicit, never an "unauthenticated" simple bind) | Nothing |
| Bad credentials | Error at login | Error at login | Nothing |
| Invalid filter | Error from the server | Checked locally before anything is sent (error 89) | Fix the filter |
| `{` `}` in a filter or DN | Literal | Literal (escaped by the drop-ins) | Nothing |
| More than 1000 results on AD | Truncated by the server's size limit | Paged: all results are returned | Nothing; add a narrower filter if you relied on the cap |
| Binary attributes (`objectGUID`, `objectSid`, photos) | Raw text | `{base64: …}` objects, or readable SID/GUID with `LDAP_SET_OPTIONS({binary: "decode"})` | Read `.base64` or opt in to decoding |
| Threads | Not thread safe | Preemptive capable | Can now run in workers and preemptive processes |
| Login state | Per process | Per process | Nothing |

## Errors

Failures raise 4D errors, as the built-in commands do, so existing
`ON ERR CALL` handlers keep working. The errors carry
`componentSignature: "ldap"` and these codes (from `Last errors`):

| errCode | Meaning |
|---|---|
| LDAP result code | The server's answer, e.g. 32 noSuchObject, 50 insufficientAccessRights |
| 49 | Bind failed (invalidCredentials) |
| 81 | Server unreachable, TLS or certificate failure |
| 89 | Invalid parameter or filter (nothing sent) |
| 1003 | No `LDAP_LOGIN` in this process (same code as the built-in) |
| -1 | Local failure (missing executable, timeout…); see the message |

## 3. Then go further, one call at a time

The drop-ins are a bridge. `LDAP_Session()` returns the `cs.ldap.LDAP` instance
behind the current login, so new code can use the full API without a second
login:

```4d
LDAP_LOGIN($url; $login; $password)
$result:=LDAP_Session().search($base; "(&(objectClass=user)(sAMAccountName={u}))"; {args: {u: $input}; scope: "sub"})
$result:=LDAP_Session().modify($result.entries[0].dn; {replace: {telephoneNumber: $phone}})
```

The end state is plain `cs.ldap.LDAP` code, ideally with Kerberos single
sign-on so that the application stores no LDAP password at all:

```4d
$ldap:=cs.ldap.LDAP.new({domain: "corp.example"; mech: "gssapi"})
```

## Not supported

* DIGEST-MD5 binds (see above).
* Plaintext LDAP binds. The CLI refuses them by design.
* Windows on ARM64 (the 4D target is `Windows-x64`).

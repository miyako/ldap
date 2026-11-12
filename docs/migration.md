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
| `digest` = MD5 (the default) | DIGEST-MD5 SASL bind | `digest` is ignored; compatibility mode uses simple bind **inside TLS**. DIGEST-MD5 is obsolete (RFC 6331) | Select explicit GSSAPI/CBT mode for hardened AD; it uses a UPN |
| `digest` = plain text | Password in clear on `ldap://` | Compatibility mode uses simple bind, always encrypted | No change unless selecting strict mode |
| Certificate checks | Depends on the platform library | Always verified against the OS trust store, with hostname verification | Internal CA not deployed on the machine: `LDAP_SET_OPTIONS({caCert: $pem})` |
| Empty `url` | Default server of the domain | DNS SRV discovery of the domain set with `LDAP_SET_OPTIONS({domain: …})` | Set the domain |
| Empty `password` | Anonymous bind | Anonymous only in compatibility simple mode; explicit mode fails; intentional SSO is separate | Select the intended mode |
| Bad credentials | Error at login | Error at login | Nothing |
| Invalid filter | Error from the server | Checked locally before anything is sent (error 89) | Fix the filter |
| `{` `}` in a filter or DN | Literal | Literal (escaped by the drop-ins) | Nothing |
| More than 1000 results on AD | Truncated by the server's size limit | Paged: all results are returned | Nothing; add a narrower filter if you relied on the cap |
| Binary attributes (`objectGUID`, `objectSid`, photos) | Raw text | `{base64: …}` objects, or readable SID/GUID with `LDAP_SET_OPTIONS({binary: "decode"})` | Read `.base64` or opt in to decoding |
| Threads | Not thread safe | Preemptive capable | Can now run in workers and preemptive processes |
| Login state | Per process | Per process | Nothing |
| Error handler | `ON ERR CALL(…; ek local)` | `ON ERR CALL(…; ek errors from components)` | Add the component-scope handler ([Errors](#errors)) |

## Authentication modes

Application-user password authentication is not replaced by Kerberos SSO.
Choose once with `LDAP_SET_OPTIONS` in each process; existing login/search/logout
method names and signatures stay unchanged.

| Mode | Configuration | Credentials |
|---|---|---|
| Compatibility simple bind over TLS | Default, or `mech: "simple"` | Login is DN, AD UPN or `DOMAIN\user`; empty password selects anonymous |
| Explicit-user SASL with required CBT | `authMode: "explicit"` (defaults `mech: "gssapi"; channelBinding: "require"`) | Login is the supplied user's UPN; nonempty password is mandatory, without preexisting tickets |
| Intentional SSO | `authMode: "sso"; mech: "gssapi"`; add `channelBinding: "require"` for strict CBT | Empty login/password; existing ticket or process logon identity |

```4d
LDAP_SET_OPTIONS({authMode: "explicit"; mech: "gssapi"; channelBinding: "require"})
LDAP_LOGIN($url; $userUPN; $password)
LDAP_SEARCH_ALL($base; ->$_entry; $filter; LDAP all levels)
LDAP_LOGOUT
```

Explicit login passes `--user=<login>`, `--mech=gssapi`,
`--channel-binding=require` and the password via stdin, **not** a simple bind.
Missing credentials raise 49 at login, never anonymous or service-account SSO.
Non-simple/password configurations also select explicit mode; required CBT
without an explicit SSO selection cannot silently become SSO. Conflicting
mechanisms, disabled TLS, insecure verification, profiles and identity/cache
overrides fail with 89 rather than downgrade. `digest` does not override the
chosen mode. A failed login clears any previous session.

Strict login performs an authenticated unpaged RootDSE search before retaining
the process-local session. Each later operation starts a new CLI and repeats
authentication using that instance's credentials. `LDAP_SET_OPTIONS` copies
its input; neither options nor sessions are shared between 4D processes.

**Not yet usable with the bundled dependency:** `cli/release.json` still pins
the real upstream v0.1.0 assets. They do not support explicit password GSSAPI
on macOS or the strict CBT contract. The component probes offline capabilities
before sending credentials and fails with local error -1 against that binary.
Do not remove the gate, substitute an unverified binary or invent a release pin.
A published supporting upstream release must be pinned with its actual asset
hashes, then the final package rebuilt and tested.

Simple TLS binds are not evidence of SASL CBT compliance. Real AD acceptance
with channel binding **Always** enforced remains **not_run** on macOS and
Windows: valid supplied credentials and trusted TLS; wrong password with no
fallback; applicable SASL without valid CBT rejected; simultaneous different
users with no identity crossover; invalid/untrusted certificate rejected; and
generic simple-bind compatibility. Record AD policy, OS/4D/CLI versions, intended
and observed identities, and server-side evidence. Absence of audit event 3075
alone is insufficient ([Microsoft reference](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)).

## Errors

Failures raise 4D errors, as the built-in commands do, but they are raised
**inside a component**. 4D sends them to the host's handler for the
`ek errors from components` scope, not to an `ek local` handler. With only a
local handler, the error is not caught and the calling method stops (verified
with tool4d 21 LTS in the host tests). Add one line wherever you install a
handler around LDAP code:

```4d
ON ERR CALL("myErrorHandler"; ek local)                   // existing
ON ERR CALL("myErrorHandler"; ek errors from components)  // add for the LDAP_* methods
```

The errors carry `componentSignature: "ldap"` and these codes (from `Last errors`):

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

The end state can be plain `cs.ldap.LDAP` code. Use explicit credentials when
the application authenticates its users; choose SSO only when that is the
application's intended authentication model:

```4d
$ldap:=cs.ldap.LDAP.new({domain: "corp.example"; authMode: "sso"; mech: "gssapi"})
```

## Not supported

* DIGEST-MD5 binds (see above).
* Plaintext LDAP binds. The CLI refuses them by design.
* Windows on ARM64 (the 4D target is `Windows-x64`).

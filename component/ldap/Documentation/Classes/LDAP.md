# LDAP

`cs.ldap.LDAP` is an LDAP client. Each call runs the bundled
[`ldap`](https://github.com/miyako/ldap-cli) executable once, as a separate
process: connect, bind, run the operation, unbind, exit.

```4d
var $ldap : cs.ldap.LDAP
var $result; $entry : Object

$ldap:=cs.ldap.LDAP.new({domain: "corp.example"; mech: "gssapi"})  // Kerberos SSO, no password
$result:=$ldap.search("OU=Staff,DC=corp,DC=example"; "(sAMAccountName={u})"; \
	{scope: "sub"; args: {u: $userInput}; attributes: ["mail"; "memberOf"]})
If ($result.ok)
	For each ($entry; $result.entries)
		// $entry.dn, $entry.attributes.mail[0]
	End for each
End if
```

## Constructor

`cs.ldap.LDAP.new(connection : Object)`

All properties are optional. Each one maps to an `ldap` option.

| Property | Type | `ldap` option | Notes |
|---|---|---|---|
| `uri` | Text or Collection | `--uri` | `ldaps://host[:636]` or `ldap://host[:389]` (StartTLS). Several URIs give failover |
| `domain` | Text | `--domain` | Find domain controllers through DNS SRV instead of `uri` |
| `site`, `gc` | Text, Boolean | `--site`, `--gc` | AD site preference, Global Catalog |
| `tls` | Text | `--tls` | `ldaps` or `starttls`. Defaults from the URI scheme |
| `caCert` | Text or Collection | `--ca-cert` | Extra trust anchor (PEM or base64 DER), *added* to the OS store |
| `tlsServerName`, `tlsMin`, `revocation` | Text | `--tls-server-name`, `--tls-min`, `--revocation` | Name to verify, `1.2`/`1.3`, `off`/`soft`/`hard` |
| `clientCert`, `certStore` | Text | `--client-cert`, `--cert-store` | `sha256/HEX`, `subject:…` or `auto`, looked up in the Keychain or Windows certificate store |
| `mech` | Text | `--mech` | `anonymous`, `simple`, `gssapi`, `spnego`, `ntlm` (Windows), `external` |
| `authMode` | Text | Component policy, no CLI flag | `explicit` = supplied UPN/password, GSSAPI and required CBT; `sso` = existing ticket/logon credentials, no password. Omit for compatibility |
| `bindDN` | Text | `--bind-dn` | Simple bind identity (DN, or UPN / `DOMAIN\user` on AD) |
| `password` | Text | `--password-stdin` | Removed from `connection` and piped to the process: never on a command line, in the environment or on disk |
| `user`, `realm`, `authzid`, `ccache` | Text | `--user`, `--realm`, `--authzid`, `--ccache` | SASL identity options |
| `saslQos`, `channelBinding`, `allowNTLM` | Text, Text, Boolean | `--sasl-qos`, `--channel-binding`, `--allow-ntlm` | |
| `connectTimeout`, `operationTimeout` | Integer | `--connect-timeout`, `--timeout` | Seconds, enforced by the CLI |
| `processTimeout` | Integer | — | Hard limit for the whole process, enforced by 4D (default 120 s). The process is killed when it expires |
| `referrals` | Text | `--referrals` | `off` (default) or `follow` |
| `binary` | Text | `--binary` | `base64` (default), `hex`, or `decode` (SID, GUID, FILETIME as text) |
| `profile` | Text | `--profile` | Named profile from the `ldap` config file |
| `insecureSkipVerify` | Boolean | `--insecure-skip-verify` | Testing only. The CLI prints a warning on every run |
| `target` | Text | — | `macOS-universal` (default on macOS) or `Windows-x64` (default on Windows) |

### Authentication modes

Simple bind inside verified TLS remains the compatibility default for password
logins. Simple bind does **not** supply SASL channel binding. To retain an
application username/password login against CBT-required AD:

```4d
$ldap:=cs.ldap.LDAP.new({uri: "ldaps://dc1.corp.example"; authMode: "explicit"; \
	user: "jdoe@CORP.EXAMPLE"; password: $password})
$result:=$ldap.search($base; "(sAMAccountName={u})"; {args: {u: $userInput}})
```

Explicit mode defaults to `mech: "gssapi"` and `channelBinding: "require"`.
Both credentials are mandatory; `user` is a UPN, not `bindDN`. A non-simple
mechanism with a password, or required CBT without `authMode: "sso"`, also
selects explicit mode. Other mechanisms, disabled TLS, insecure verification,
NTLM fallback, profiles, and `bindDN` / `ccache` / `authzid` / `realm` overrides
are rejected, not substituted. Configure the trust store or `caCert` instead
of disabling verification.

Intentional SSO is separate:
`{authMode: "sso"; mech: "gssapi"; channelBinding: "require"}` uses existing
tickets/logon credentials and refuses a password. Legacy password-free
`mech: "gssapi"` remains available outside required-CBT mode.

Before **each** strict connection, the component runs offline `ldap capabilities`
without credentials. It requires JSON `{"schema":1,"features":[...]}` containing
`channel-binding-require` and, for explicit mode, `explicit-credentials-sasl`.
Unknown commands, malformed responses, missing platform features and probe
failures stop the operation before password transmission. The bundled
[CLI v0.2.0](https://github.com/miyako/ldap-cli/releases/tag/v0.2.0) provides
these capabilities and acquires isolated credentials for the supplied user
without requiring preexisting tickets. Simple bind, explicit-user SASL and SSO
remain distinct choices. Actual Windows directory authentication and real AD
Always-policy acceptance on both platforms remain unverified.

## Templates: injection-safe filters and DNs

Bases, filters, DNs and RDNs are **templates**. `{name}` is replaced by
`options.args.name`, escaped for where it appears (RFC 4515 in a filter,
RFC 4514 in a DN). Text in the template keeps its meaning, so `(cn={q}*)` is a
safe prefix search: a `*` typed by the user is escaped, the template's `*` stays
a wildcard. Write `{{` and `}}` for literal braces.

```4d
// Never concatenate user input into a filter:
$result:=$ldap.search($base; "(&(objectClass=user)(cn={q}*))"; {args: {q: $input}})
```

## Result object

Every function except the offline helpers returns:

| Property | Type | Description |
|---|---|---|
| `ok` | Boolean | `True` on success |
| `stdout`, `stderr` | Text | Raw process output |
| `exitCode` | Integer | Process exit code (absent if the process never started) |
| `error` | Object | `{code; message; resultCode?; details?}` when `ok` is `False` |
| `entries` / `entry` / `value` | | Function-specific payload |

`error.code` values:

| Code | Meaning |
|---|---|
| `ldap` | The server returned an LDAP error. `error.resultCode` holds it (32 noSuchObject, 49 invalidCredentials, 50 insufficientAccessRights, 68 entryAlreadyExists…) |
| `authentication` | The bind failed before an LDAP result (Kerberos, certificate…) |
| `connection` | DNS, TCP or TLS failure, including certificate verification |
| `usage` | Invalid option, filter or template. Nothing was sent |
| `process_terminated` | `processTimeout` expired or the process was killed |
| `missing_executable`, `launch_failed`, `invalid_argument`, `invalid_protocol`, `unsupported`, `unsupported_architecture` | Local errors |

## Functions

### execute()

`execute(command : Collection {; settings : Object}) : Object`

Runs **any** `ldap` command with this instance's connection options. `command`
is the argument list after the global options, so every CLI option is
available, including ones that have no dedicated function yet.

Write option values as one `--flag=value` element and put positional values
after `"--"`: then a value that starts with `-` cannot be read as an option.
The class's own functions do this.

`settings`: `{stdin: Text; timeout: Integer; connect: Boolean}`. `connect: False`
omits the connection options (offline commands such as `escape` and `dn`).
`stdin` is refused when the bind password already uses it.
In strict mode authentication/TLS overrides in `command` are refused; set them
on `connection` instead. `connect: False` is for offline commands only and
intentionally omits all connection settings and authentication checks.

```4d
// Dynamic entry refresh (RFC 2589): no dedicated function needed
$result:=$ldap.execute(["exop"; "refresh"; "--value="+$dn; "--ttl=300"])
```

### search()

`search(base : Text; filter : Text {; options : Object}) : Object`

`$result.entries` is a Collection of `{dn: Text; attributes: {name: Collection}}`.
Attribute values are Text, or `{base64}` / `{hex}` objects for binary values.

| Option | Description |
|---|---|
| `scope` | `base`, `one`, `sub` (CLI default), `children` |
| `attributes` | Collection of names; `"+"` = operational, `"1.1"` = none |
| `args` | Template values |
| `pageSize` | Paging (CLI default 500, `0` disables). The server's size limit does not truncate paged results |
| `sort` | Server-side sort, e.g. `["-whenCreated"; "cn"]` |
| `sizeLimit`, `timeLimit`, `deref`, `typesOnly`, `rawFilter` | As in `ldap search --help` |
| `controls` | Collection of `OID[!][=b64:VALUE]` request controls |

Large AD groups are read in full (range retrieval) automatically. An empty
`base` uses the server's default naming context.

### findOne()

`findOne(base : Text; filter : Text {; options : Object}) : Object` returns the
first entry in `$result.entry`, or `Null`.

### add()

`add(dn : Text; attributes : Object {; options : Object}) : Object`

```4d
$result:=$ldap.add("CN={cn},OU=Staff,DC=corp,DC=example"; \
	{objectClass: ["top"; "person"; "organizationalPerson"; "user"]; sn: $sn; jpegPhoto: $photoBlob}; \
	{args: {cn: $fullName}})
```

A Collection gives several values; a `4D.Blob` is sent as binary.

### modify()

`modify(dn : Text; changes : Object {; options : Object}) : Object`

```4d
$result:=$ldap.modify($dn; {replace: {mail: $mail}; add: {memberOf: $group}; delete: {pager: Null}; increment: {uidNumber: 1}})
```

`delete: {attr: Null}` removes every value; `delete: {attr: value}` removes one.

### delete()

`delete(dn : Text {; options : Object}) : Object`. `options.subtree: True`
deletes the entry and everything below it (with the AD tree-delete control when
the server offers it).

### rename()

`rename(dn : Text; newRDN : Text {; options : Object}) : Object`.
`options.newSuperior` moves the entry; `options.keepOldRDN` keeps the old RDN value.

### compare()

`compare(dn : Text; attribute : Text; value : Text {; options : Object}) : Object`.
`$result.value` is `True` or `False`.

### whoami()

`whoami() : Object`. `$result.value` is the identity the server sees
(`dn:…` or `u:DOMAIN\user`).

### changePassword()

`changePassword(newPassword : Text {; options : Object}) : Object` resets the
password of `options.dn` (default: the bound identity). `options.method`:
`auto` (RFC 3062, or `unicodePwd` on AD), `exop`, `ad`, `replace`.

The new password is piped on stdin, so the bind must not use a password:
bind with `mech: "gssapi"` or `mech: "external"`. Otherwise the function returns
`error.code: "unsupported"`.

### probe()

`probe() : Object` returns the TLS version, the server certificate chain with
SHA-256 fingerprints and the RootDSE, as Text in `$result.value`.

### Offline helpers

These run without connecting and return Text (empty on error).

| Function | Example |
|---|---|
| `escapeFilter(value)` | `a*(b)` → `a\2a\28b\29` |
| `escapeDN(value)` | `#Smith, John` → `\#Smith\, John` |
| `buildDN(template; args)` | `buildDN("CN={cn},OU=Users,DC=corp"; {cn: "Smith, John"})` |
| `parseDN(dn)` | Returns a Collection of RDNs |
| `version()` | Returns an Object; `$result.value` is the CLI version |

## Concurrency

Instances hold configuration only, no connection. Calls are synchronous and can
run in any process, including preemptive processes and workers.
Each instance retains its own password in memory to authenticate each child
process; it is not placed in the public `connection` object, argv or environment.
The drop-ins copy options and keep their session in process-local variables.
Do not share a mutable instance across different application users. Log out
when finished; no deterministic secure erasure of 4D-managed Text is claimed.
Real simultaneous-user AD isolation remains an outstanding acceptance check.

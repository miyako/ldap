# Extending the component

The built-in commands are fixed: four commands, search only. This component is
4D code over a documented command-line tool, so new features are a few lines of
4D, written in the host or contributed upstream.

## Layers

```
host code ─┬─ LDAP_LOGIN / LDAP_Search …   drop-ins (Methods/)
           └─ cs.ldap.LDAP                  high-level API (Classes/LDAP.4dm)
                 └─ execute()               any ldap command + connection options
                       └─ cs._CLI           finds Resources/bin/<OS>/ldap[.exe]
                             └─ cs._Process 4D.SystemWorker: quoting, stdin, timeout, exit status
                                   └─ ldap  miyako/ldap-cli (Rust; Wldap32 / OpenLDAP)
```

## 1. Use any CLI feature now, with execute()

Everything `ldap` can do is reachable through `execute()`, with the instance's
connection, TLS and authentication options applied:

```4d
// Any request control, e.g. LDAP_SERVER_SHOW_DELETED_OID to see tombstones
$result:=$ldap.search("CN=Deleted Objects,DC=corp,DC=example"; "(isDeleted=TRUE)"; \
	{controls: ["1.2.840.113556.1.4.417"]; scope: "one"})

// An extended operation by OID
$result:=$ldap.execute(["exop"; "1.3.6.1.4.1.4203.1.11.3"])

// LDIF import: a 4D.File argument is expanded to the native path for you
$result:=$ldap.execute(["add"; "--file"; $ldifFile; "--continue-on-error"])  // 4D.File: expanded by _Process
```

## 2. Wrap a recurring task in your own class

Compose the client in a host class to give a business operation a name:

```4d
// Class Directory (host)
property _ldap : cs.ldap.LDAP

Class constructor()
	This._ldap:=cs.ldap.LDAP.new({domain: "corp.example"; mech: "gssapi"; binary: "decode"})

Function isMemberOf($user : Text; $groupDN : Text)->$member : Boolean
	var $result : Object
	// LDAP_MATCHING_RULE_IN_CHAIN: nested group membership resolved by AD
	$result:=This._ldap.findOne(""; "(&(sAMAccountName={u})(memberOf:1.2.840.113556.1.4.1941:={g}))"; \
		{args: {u: $user; g: $groupDN}; scope: "sub"; attributes: ["1.1"]})
	$member:=$result.ok && ($result.entry#Null)
```

## 3. Add a function to the component

A new high-level function builds an argument Collection and calls `execute()`.
Arguments are passed to the process one by one, quoted by `_Process`; nothing
goes through a shell, so no escaping is needed in 4D. Pass option values as
`"--flag="+$value` so a value starting with `-` is not read as an option:

```4d
Function refresh($dn : Text; $ttl : Integer)->$result : Object
	$result:=This.execute(["exop"; "refresh"; "--value="+$dn; "--ttl="+String($ttl)])
```

## 4. Add a feature to the CLI

When the protocol work belongs in native code (a new control, a new SASL
mechanism, a new output format), add it to
[miyako/ldap-cli](https://github.com/miyako/ldap-cli), release it, and update
the binaries in `Resources/bin`. The 4D side is then one `execute()` call.
Because the CLI is a normal command, the feature can be tested from a terminal
and in CI without 4D.

## 5. Configure without code

`ldap` reads named profiles from `~/.config/ldap/config.toml` (macOS) or
`%APPDATA%\ldap\config.toml` (Windows). `cs.ldap.LDAP.new({profile: "corp"})`
uses one. Profiles never hold passwords.

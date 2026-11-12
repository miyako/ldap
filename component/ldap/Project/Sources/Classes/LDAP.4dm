// cs.ldap.LDAP — LDAP client backed by the bundled `ldap` CLI (miyako/ldap-cli).
//
// Option values are passed as single --flag=value tokens and positional values after
// "--", so a value that starts with "-" is never read as an option.
//
// Every call runs one short-lived `ldap` process: connect, bind, operate, unbind.
// No connection state is shared between 4D processes, so an instance can be used
// from any process, including preemptive ones.

property connection : Object  // non-secret connection options (see Documentation/Classes/LDAP.md)
property _cli : cs._CLI
property _password : Text  // never put on argv or in the environment: piped to --password-stdin

Class constructor($connection : Object)
	var $target; $mode; $mechanism; $binding : Text
	This.connection:=($connection=Null) ? New object : OB Copy($connection)
	This._password:=""
	If (Value type(This.connection.password)=Is text)
		This._password:=This.connection.password
	End if
	OB REMOVE(This.connection; "password")
	$mode:=(Value type(This.connection.authMode)=Is text) ? This.connection.authMode : ""
	$mechanism:=(Value type(This.connection.mech)=Is text) ? This.connection.mech : ""
	$binding:=(Value type(This.connection.channelBinding)=Is text) ? This.connection.channelBinding : ""
	If (This.connection.authMode=Null)
		If (($binding="require") | ((This._password#"") & ($mechanism#"") & ($mechanism#"simple")))
			This.connection.authMode:="explicit"
			$mode:="explicit"
		End if
	End if
	If ($mode="explicit")
		If (This.connection.mech=Null)
			This.connection.mech:="gssapi"
		End if
		If (This.connection.channelBinding=Null)
			This.connection.channelBinding:="require"
		End if
	End if
	$target:=(Value type(This.connection.target)=Is text) ? This.connection.target : (Is Windows ? "Windows-x64" : "macOS-universal")
	This._cli:=cs._CLI.new("ldap"; $target)

	// MARK: - generic

Function execute($command : Collection; $settings : Object)->$result : Object
	// Run any ldap-cli command with this instance's connection options.
	// $command is argv after the global options, e.g. ["exop"; "refresh"; "--value"; $dn; "--ttl"; "300"].
	// $settings: {stdin: Text; timeout: Integer (seconds); connect: Boolean (default True)}
	var $arguments : Collection
	var $process; $authentication : Object
	If ($command=Null)
		return This._fail("invalid_argument"; "command Collection is required")
	End if
	$process:=New object("timeout"; This._timeout())
	$arguments:=New collection
	If (($settings=Null) || (Value type($settings.connect)#Is boolean) || $settings.connect)
		$authentication:=This._authentication($command)
		If (Not($authentication.ok))
			return $authentication
		End if
		If ($authentication.explicit | $authentication.strict)
			$result:=This._checkCapabilities(This._cli.execute(New collection("capabilities"); $process); $authentication.explicit)
			If (Not($result.ok))
				return $result
			End if
		End if
		$arguments:=This._globalArguments()
		If (This._password#"")
			$process.stdin:=This._password
		End if
	End if
	If ($settings#Null)
		If (Value type($settings.stdin)=Is text)
			If (Value type($process.stdin)=Is text)
				return This._fail("invalid_argument"; "stdin already carries the bind password")
			End if
			$process.stdin:=$settings.stdin
		End if
		If ((Value type($settings.timeout)=Is real) | (Value type($settings.timeout)=Is longint))
			$process.timeout:=$settings.timeout
		End if
	End if
	$result:=This._classify(This._cli.execute($arguments.combine($command); $process))

	// MARK: - directory operations

Function search($base : Text; $filter : Text; $options : Object)->$result : Object
	// $base and $filter are templates: {name} is replaced by $options.args.name,
	// escaped (RFC 4514 / RFC 4515) for where it appears.
	// $options: {scope; attributes; args; sizeLimit; timeLimit; pageSize; sort; deref; typesOnly; rawFilter; controls}
	var $command : Collection
	var $payload : Variant
	$options:=($options=Null) ? New object : $options
	$command:=New collection("--format=json"; "search")
	This._option($command; "--base"; $base)
	This._option($command; "--filter"; $filter)
	This._option($command; "--scope"; $options.scope)
	This._option($command; "--size-limit"; $options.sizeLimit)
	This._option($command; "--time-limit"; $options.timeLimit)
	This._option($command; "--page-size"; $options.pageSize)
	This._option($command; "--deref"; $options.deref)
	This._option($command; "--sort"; (Value type($options.sort)=Is collection) ? $options.sort.join(",") : $options.sort)
	If ($options.typesOnly=True)
		$command.push("--types-only")
	End if
	If ($options.rawFilter=True)
		$command.push("--raw-filter")
	End if
	This._templateArguments($command; $options)
	If (Value type($options.attributes)=Is collection)
		$command.push("--")
		$command.combine($options.attributes)
	End if
	$result:=This.execute($command; $options)
	If (Not($result.ok))
		return $result
	End if
	$payload:=This._parse($result.stdout)
	If (Value type($payload)#Is collection)
		return This._protocolError($result; "search output must be a JSON array")
	End if
	$result.entries:=$payload  // [{dn: Text; attributes: {name: [values]}}]

Function findOne($base : Text; $filter : Text; $options : Object)->$result : Object
	// First matching entry (or Null) in $result.entry.
	$options:=($options=Null) ? New object : OB Copy($options)
	$options.sizeLimit:=1
	$result:=This.search($base; $filter; $options)
	If ($result.ok)
		$result.entry:=($result.entries.length>0) ? $result.entries[0] : Null
	End if

Function add($dn : Text; $attributes : Object; $options : Object)->$result : Object
	// $attributes: {cn: "Ann"; objectClass: ["top"; "person"]; jpegPhoto: 4D.Blob}
	var $command : Collection
	var $name : Text
	$command:=New collection("add"; "--dn="+$dn)
	For each ($name; $attributes)
		This._values($command; "--attr"; $name; $attributes[$name]; False)
	End for each
	This._templateArguments($command; $options)
	$result:=This.execute($command; $options)

Function modify($dn : Text; $changes : Object; $options : Object)->$result : Object
	// $changes: {add: {…}; replace: {…}; delete: {attr: Null (all values) | value(s)}; increment: {attr: n}}
	var $command : Collection
	var $kind; $name : Text
	$command:=New collection("modify"; "--dn="+$dn)
	For each ($kind; New collection("add"; "replace"; "delete"; "increment"))
		If (Value type($changes[$kind])=Is object)
			For each ($name; $changes[$kind])
				This._values($command; "--"+$kind; $name; $changes[$kind][$name]; $kind="delete")
			End for each
		End if
	End for each
	This._templateArguments($command; $options)
	$result:=This.execute($command; $options)

Function delete($dn : Text; $options : Object)->$result : Object
	// $options.subtree: delete the entry and everything below it
	var $command : Collection
	$command:=New collection("delete"; "--dn="+$dn)
	If (($options#Null) && ($options.subtree=True))
		$command.push("--subtree")
	End if
	This._templateArguments($command; $options)
	$result:=This.execute($command; $options)

Function rename($dn : Text; $newRDN : Text; $options : Object)->$result : Object
	// $options: {newSuperior: DN template; keepOldRDN: Boolean}
	var $command : Collection
	$command:=New collection("modrdn"; "--dn="+$dn; "--new-rdn="+$newRDN)
	If ($options#Null)
		This._option($command; "--new-superior"; $options.newSuperior)
		If ($options.keepOldRDN=True)
			$command.push("--keep-old-rdn")
		End if
	End if
	This._templateArguments($command; $options)
	$result:=This.execute($command; $options)

Function compare($dn : Text; $attribute : Text; $value : Text; $options : Object)->$result : Object
	// $result.value: True / False (exit code 1 means "false", not a failure)
	var $command : Collection
	$command:=New collection("compare"; "--dn="+$dn; "--attr="+$attribute; "--value="+$value)
	This._templateArguments($command; $options)
	$result:=This.execute($command; $options)
	Case of
		: ($result.ok)
			$result.value:=True
		: (($result.exitCode=1) & ($result.error.code="cli_error"))
			$result.value:=False
			$result.ok:=True
			OB REMOVE($result; "error")
	End case

Function whoami()->$result : Object
	$result:=This._text(This.execute(New collection("whoami")))

Function changePassword($newPassword : Text; $options : Object)->$result : Object
	// Admin reset of $options.dn (default: the bound identity).
	// $options: {dn: DN template; args; method: "auto"|"exop"|"ad"|"replace"}
	// The new password is piped on stdin, so the bind itself must not need a
	// password: use Kerberos (mech "gssapi") or a client certificate (mech "external").
	var $command : Collection
	If (This._password#"")
		return This._fail("unsupported"; "stdin carries the bind password; bind with mech \"gssapi\" or \"external\" to reset passwords")
	End if
	$command:=New collection("passwd"; "--new-password-stdin")
	If ($options#Null)
		This._option($command; "--dn"; $options.dn)
		This._option($command; "--method"; $options.method)
	End if
	This._templateArguments($command; $options)
	$result:=This.execute($command; New object("stdin"; $newPassword))

Function probe()->$result : Object
	// TLS version, server chain fingerprints and RootDSE, as text in $result.value
	$result:=This._text(This.execute(New collection("probe")))

	// MARK: - offline helpers (no connection)

Function escapeFilter($value : Text)->$escaped : Text
	$escaped:=This._offline(New collection("escape"; "filter"; "--"; $value))

Function escapeDN($value : Text)->$escaped : Text
	$escaped:=This._offline(New collection("escape"; "dn"; "--"; $value))

Function buildDN($template : Text; $args : Object)->$dn : Text
	var $command : Collection
	$command:=New collection("dn"; "build")
	This._templateArguments($command; New object("args"; $args))
	$dn:=This._offline($command.push("--"; $template))

Function parseDN($dn : Text)->$rdns : Collection
	var $result : Object
	var $payload : Variant
	$result:=This.execute(New collection("dn"; "parse"; "--"; $dn); New object("connect"; False))
	If ($result.ok)
		$payload:=This._parse($result.stdout)
		If (Value type($payload)=Is collection)
			$rdns:=$payload
		End if
	End if

Function version()->$result : Object
	$result:=This._text(This.execute(New collection("--version"); New object("connect"; False)))

	// MARK: - internals

Function _authentication($command : Collection)->$result : Object
	var $c : Object
	var $mode; $user; $name; $flag : Text
	var $argument : Variant
	var $equals : Integer
	var $explicit; $strict : Boolean
	$c:=This.connection
	For each ($name; New collection("mech"; "channelBinding"; "bindDN"; "user"; "ccache"; "authzid"; "realm"; "profile"))
		If ($c[$name]#Null)
			If (Value type($c[$name])#Is text)
				return This._fail("usage"; $name+" must be Text")
			End if
		End if
	End for each
	$mode:=""
	If ($c.authMode#Null)
		If (Value type($c.authMode)#Is text)
			return This._fail("usage"; "authMode must be explicit or sso")
		End if
		$mode:=$c.authMode
		If (($mode#"explicit") & ($mode#"sso"))
			return This._fail("usage"; "authMode must be explicit or sso")
		End if
	End if
	$strict:=($c.channelBinding="require")
	$explicit:=($mode="explicit") | ($strict & ($mode#"sso")) | ((This._password#"") & ($c.mech#Null) & ($c.mech#"simple"))
	If (($mode="sso") & (This._password#""))
		return This._fail("usage"; "SSO must not receive a password; select authMode explicit for user credentials")
	End if
	If ($explicit)
		If (($c.mech#"gssapi") | Not($strict))
			return This._fail("usage"; "Explicit authentication requires mech gssapi and channelBinding require")
		End if
		$user:=""
		If (Value type($c.user)=Is text)
			$user:=$c.user
		End if
		If (($user="") | (This._password=""))
			return This._fail("authentication"; "Explicit authentication requires a user UPN and a nonempty password")
		End if
		If ((Position("@"; $user; *)<=1) | (Position("@"; $user; *)=Length($user)) | (Position("\\"; $user; *)>0))
			return This._fail("usage"; "Explicit authentication user must be a UPN, for example user@CORP.EXAMPLE")
		End if
	End if
	If ($strict | $explicit)
		If ($c.mech#"gssapi")
			return This._fail("usage"; "CBT-required authentication requires mech gssapi")
		End if
		If (($c.insecureSkipVerify=True) | ($c.allowNTLM=True))
			return This._fail("usage"; "CBT-required authentication forbids insecureSkipVerify and allowNTLM")
		End if
		If ($c.tls#Null)
			If (Value type($c.tls)#Is text)
				return This._fail("usage"; "CBT-required authentication needs TLS ldaps or starttls")
			End if
			If (($c.tls#"ldaps") & ($c.tls#"starttls"))
				return This._fail("usage"; "CBT-required authentication needs TLS ldaps or starttls")
			End if
		End if
		If (($c.profile#Null) & ($c.profile#""))
			return This._fail("usage"; "CBT-required authentication must not use a profile")
		End if
		If ((($c.bindDN#Null) & ($c.bindDN#"")) | (($c.ccache#Null) & ($c.ccache#"")) | (($c.authzid#Null) & ($c.authzid#"")) | (($c.realm#Null) & ($c.realm#"")))
			return This._fail("usage"; "CBT-required authentication forbids bindDN, ccache, authzid and realm overrides")
		End if
		If ($command#Null)
			For each ($argument; $command)
				If (Value type($argument)=Is text)
					If ($argument="--")
						break
					End if
					$equals:=Position("="; $argument; *)
					$flag:=($equals>0) ? Substring($argument; 1; $equals-1) : $argument
					If ((New collection("--mech"; "--channel-binding"; "--user"; "--bind-dn"; "--realm"; "--authzid"; "--ccache"; "--profile"; "--password-file"; "--password-stdin"; "--password-env"; "--tls"; "--allow-plaintext"; "--insecure-skip-verify"; "--allow-ntlm"; "--client-cert-password-stdin").indexOf($flag)>=0) | (Position("-M"; $flag; *)=1) | (Position("-D"; $flag; *)=1) | (Position("-U"; $flag; *)=1))
						return This._fail("usage"; "CBT-required authentication options must be set on the connection, not execute")
					End if
				End if
			End for each
		End if
	End if
	If ($mode="sso")
		If (($c.mech#"gssapi") & ($c.mech#"spnego"))
			return This._fail("usage"; "SSO requires mech gssapi or spnego")
		End if
	End if
	$result:=New object("ok"; True; "explicit"; $explicit; "strict"; $strict)

Function _checkCapabilities($result : Object; $explicit : Boolean)->$checked : Object
	var $payload : Variant
	var $feature : Variant
	var $supportsExplicit; $supportsBinding : Boolean
	$checked:=$result
	If (Not($result.ok))
		$result.error:=New object("code"; "unsupported"; "message"; "Bundled ldap CLI cannot confirm strict authentication capabilities; a verified upstream release is required"; "details"; $result.error)
		return
	End if
	$payload:=This._parse($result.stdout)
	If (Value type($payload)#Is object)
		return This._protocolError($result; "capabilities must return a JSON object")
	End if
	If ((Value type($payload.schema)#Is real) & (Value type($payload.schema)#Is longint))
		return This._protocolError($result; "capabilities schema must be 1")
	End if
	If ($payload.schema#1)
		return This._protocolError($result; "capabilities schema must be 1")
	End if
	If (Value type($payload.features)#Is collection)
		return This._protocolError($result; "capabilities features must be a Text collection")
	End if
	For each ($feature; $payload.features)
		If (Value type($feature)#Is text)
			return This._protocolError($result; "capabilities features must be a Text collection")
		End if
		If ((Length($feature)=Length("channel-binding-require")) & (Position("channel-binding-require"; $feature; *)=1))
			$supportsBinding:=True
		End if
		If ((Length($feature)=Length("explicit-credentials-sasl")) & (Position("explicit-credentials-sasl"; $feature; *)=1))
			$supportsExplicit:=True
		End if
	End for each
	If (Not($supportsBinding) | ($explicit & Not($supportsExplicit)))
		$result.ok:=False
		$result.error:=New object("code"; "unsupported"; "message"; "Bundled ldap CLI lacks required authentication capabilities on this platform")
	End if

Function _globalArguments()->$arguments : Collection
	var $c : Object
	var $value : Variant
	$c:=This.connection
	$arguments:=New collection
	For each ($value; This._list($c.uri))
		$arguments.push("--uri="+$value)
	End for each
	For each ($value; This._list($c.caCert))
		$arguments.push("--ca-cert="+$value)
	End for each
	This._option($arguments; "--domain"; $c.domain)
	This._option($arguments; "--site"; $c.site)
	This._option($arguments; "--tls"; $c.tls)
	This._option($arguments; "--connect-timeout"; $c.connectTimeout)
	This._option($arguments; "--timeout"; $c.operationTimeout)
	This._option($arguments; "--referrals"; $c.referrals)
	This._option($arguments; "--profile"; $c.profile)
	This._option($arguments; "--tls-server-name"; $c.tlsServerName)
	This._option($arguments; "--tls-min"; $c.tlsMin)
	This._option($arguments; "--revocation"; $c.revocation)
	This._option($arguments; "--client-cert"; $c.clientCert)
	This._option($arguments; "--cert-store"; $c.certStore)
	This._option($arguments; "--mech"; $c.mech)
	This._option($arguments; "--bind-dn"; $c.bindDN)
	This._option($arguments; "--user"; $c.user)
	This._option($arguments; "--realm"; $c.realm)
	This._option($arguments; "--authzid"; $c.authzid)
	This._option($arguments; "--ccache"; $c.ccache)
	This._option($arguments; "--sasl-qos"; $c.saslQos)
	This._option($arguments; "--channel-binding"; $c.channelBinding)
	This._option($arguments; "--binary"; $c.binary)
	If ($c.gc=True)
		$arguments.push("--gc")
	End if
	If ($c.allowNTLM=True)
		$arguments.push("--allow-ntlm")
	End if
	If ($c.insecureSkipVerify=True)
		$arguments.push("--insecure-skip-verify")
	End if
	If (This._password#"")
		$arguments.push("--password-stdin")
	End if

Function _list($value : Variant)->$list : Collection
	Case of
		: (Value type($value)=Is collection)
			$list:=$value
		: (Value type($value)=Is text)
			$list:=New collection($value)
		Else
			$list:=New collection
	End case

Function _timeout()->$seconds : Integer
	// Hard limit for the whole process; it must outlive the CLI's own
	// connect and per-operation timeouts, and paged searches of large directories.
	$seconds:=Num(This.connection.processTimeout)
	If ($seconds<=0)
		$seconds:=120
	End if

Function _option($arguments : Collection; $flag : Text; $value : Variant)
	Case of
		: (Value type($value)=Is text)
			If ($value#"")
				$arguments.push($flag+"="+$value)
			End if
		: ((Value type($value)=Is real) | (Value type($value)=Is longint))
			$arguments.push($flag+"="+String($value))
	End case

Function _templateArguments($arguments : Collection; $options : Object)
	// {name} placeholders: the CLI escapes each value for the context it appears in
	var $name : Text
	If ($options=Null)
		return
	End if
	If (Value type($options.args)=Is object)
		For each ($name; $options.args)
			$arguments.push("--arg="+$name+"="+String($options.args[$name]))
		End for each
	End if
	If (Value type($options.controls)=Is collection)
		For each ($name; $options.controls)
			$arguments.push("--control="+$name)
		End for each
	End if

Function _values($arguments : Collection; $flag : Text; $name : Text; $value : Variant; $nameOnlyIfNull : Boolean)
	var $item : Variant
	var $blob : Blob
	var $encoded : Text
	Case of
		: ((Value type($value)=Is null) & $nameOnlyIfNull)
			$arguments.push($flag+"="+$name)
		: (Value type($value)=Is collection)
			For each ($item; $value)
				This._values($arguments; $flag; $name; $item; False)
			End for each
		: (Value type($value)=Is object)
			If (OB Instance of($value; 4D.Blob))
				$blob:=$value
				BASE64 ENCODE($blob; $encoded)
				$arguments.push($flag+"="+$name+":=b64:"+$encoded)
			End if
		Else
			$arguments.push($flag+"="+$name+"="+String($value))
	End case

Function _classify($result : Object)->$classified : Object
	// ldap-cli exit codes: 2 usage, 3 connection/TLS, 4 authentication, 10+N LDAP result code N
	$classified:=$result
	// 4D evaluates operators left to right: keep the parentheses
	If ($result.ok || ((Value type($result.exitCode)#Is real) && (Value type($result.exitCode)#Is longint)))
		return
	End if
	Case of
		: ($result.exitCode=2)
			$result.error.code:="usage"
		: ($result.exitCode=3)
			$result.error.code:="connection"
		: ($result.exitCode=4)
			$result.error.code:="authentication"
		: ($result.exitCode>=10)
			$result.error.code:="ldap"
			$result.error.resultCode:=$result.exitCode-10
	End case

Function _parse($text : Text)->$payload : Variant
	var $previous : Text
	var CLI_LastErrors : Collection
	$previous:=Method called on error(ek local)
	CLI_LastErrors:=Null
	ON ERR CALL("_CaptureError"; ek local)
	$payload:=JSON Parse($text)
	ON ERR CALL($previous; ek local)
	If (CLI_LastErrors#Null)
		$payload:=Null
	End if
	CLI_LastErrors:=Null

Function _text($result : Object)->$decoded : Object
	var $value : Text
	$decoded:=$result
	If ($result.ok)
		$value:=$result.stdout
		While (($value#"") && ((Substring($value; Length($value))="\n") | (Substring($value; Length($value))="\r")))
			$value:=Substring($value; 1; Length($value)-1)
		End while
		$result.value:=$value
	End if

Function _offline($command : Collection)->$text : Text
	var $result : Object
	$result:=This._text(This.execute($command; New object("connect"; False)))
	$text:=$result.ok ? $result.value : ""

Function _protocolError($result : Object; $message : Text)->$failed : Object
	$result.ok:=False
	$result.error:=New object("code"; "invalid_protocol"; "message"; $message)
	$failed:=$result

Function _fail($code : Text; $message : Text)->$result : Object
	$result:=New object("ok"; False; "error"; New object("code"; $code; "message"; $message))

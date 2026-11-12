//%attributes = {"invisible":true}
var $ignored : Integer
var $parameter; $name; $target : Text
var $folderPath : Text
var $request; $result; $report; $options; $capability : Object
var $tool; $secret : cs.ldap.LDAP
var $explicit; $other : cs.ldap.LDAP
var $ignoredObject : Object
var HOST_Errors : Collection
var HOST_ErrorScope : Text
var $requestFile; $statusFile : 4D.File
var $renamedExecutable : 4D.File
var $cases : Collection
var $invalid : Variant
var HOST_StatusFile : 4D.File
var HOST_Phase : Text
var HOST_PreviousHandler : Text
$ignored:=Get database parameter(User param value; $parameter)
If (Is Windows)
	$requestFile:=File($parameter; fk platform path)
Else
	$requestFile:=File($parameter; fk posix path)
End if
$request:=JSON Parse($requestFile.getText())
If (Is Windows)
	$statusFile:=File($request.status; fk platform path)
Else
	$statusFile:=File($request.status; fk posix path)
End if
$statusFile.setText("{\"success\":false,\"phase\":\"starting\"}")
HOST_StatusFile:=$statusFile
HOST_Phase:="constructor"
HOST_PreviousHandler:=Method called on error(ek local)
ON ERR CALL("Host_error"; ek local)
$target:="macOS-universal"
If (Is Windows)
	$target:="Windows-x64"
End if
$tool:=cs.ldap.LDAP.new(New object("target"; $target))
// Quoting round trips through the real CLI: RFC 4515 escaping changes only * ( ) \ NUL
$cases:=New collection("world"; "path with spaces"; "quote \" and \\ slash"; "line\nbreak"; "日本語"; "$() ; & % !")
$report:=New object("success"; True; "finished"; False; "cases"; New collection)
$report.compiled:=$tool._cli.compiled
HOST_Phase:="renamed executable"
If (Is Windows)
	$renamedExecutable:=File($request.executable; fk platform path)
Else
	$renamedExecutable:=File($request.executable; fk posix path)
End if
$report.renamedExecutable:=cs.ldap._Process.new().execute($renamedExecutable; New collection("--version"))
If (Not($report.renamedExecutable.ok))
	$report.success:=False
End if
HOST_Phase:="feature cases"
If ($request.expectCompiled#$report.compiled)
	$report.success:=False
End if
For each ($name; $cases)
	$result:=$tool._text($tool.execute(New collection("escape"; "filter"; $name); New object("connect"; False)))
	$report.cases.push($result)
	If (Not($result.ok))
		$report.success:=False
	End if
End for each
$result:=$tool.version()
$report.version:=$result
If (Not($result.ok))
	$report.success:=False
End if
HOST_Phase:="offline helpers"
$report.escapedFilter:=$tool.escapeFilter("a*(b)")
$report.escapedDN:=$tool.escapeDN("#Smith, John")
$report.hyphenFilter:=$tool.escapeFilter("--version")
$report.hyphenDN:=$tool.buildDN("-CN={cn}"; New object("cn"; "-x,y"))
$report.builtDN:=$tool.buildDN("CN={cn},OU=Users,DC=corp"; New object("cn"; "Smith, John"))
$report.missingArgDN:=$tool.buildDN("CN={cn},OU=Users"; New object)
$report.parsedDN:=$tool.parseDN("CN=Smith\\, John,OU=Users,DC=corp")
HOST_Phase:="error classification"
$report.usage:=$tool.search(""; "")
$report.connection:=cs.ldap.LDAP.new(New object("target"; $target; "uri"; "ldaps://127.0.0.1:1"; "connectTimeout"; 2)).whoami()
$secret:=cs.ldap.LDAP.new(New object("target"; $target; "uri"; "ldaps://127.0.0.1:1"; "bindDN"; "cn=a"; "password"; "s3cret"))
$report.passwordKept:=($secret.connection.password#Null)
$report.stdinConflict:=$secret.execute(New collection("whoami"); New object("stdin"; "x"))
$report.passwordBind:=$secret.whoami()
HOST_Phase:="authentication modes"
$options:=New object("target"; $target; "uri"; "ldaps://127.0.0.1:1"; "authMode"; "explicit"; "user"; "alice@CORP.EXAMPLE"; "password"; "alice-secret")
$explicit:=cs.ldap.LDAP.new($options)
$options.user:="bob@CORP.EXAMPLE"
$options.password:="bob-secret"
$other:=cs.ldap.LDAP.new($options)
$report.explicitArguments:=$explicit._globalArguments()
$report.otherArguments:=$other._globalArguments()
$report.explicitPolicy:=$explicit._authentication()
$report.explicitPasswordKept:=($explicit.connection.password#Null)
$report.independentPasswords:=($explicit._password#"") & ($other._password#"") & ($explicit._password#$other._password)
$report.bundledCapabilities:=$explicit._checkCapabilities(cs.ldap._CLI.new("ldap"; $target).execute(New collection("capabilities")); True)
$report.strictConnection:=$explicit.whoami()
$report.strictCompare:=$explicit.compare("DC=corp"; "cn"; "alice")
$report.commandOverride:=$explicit.execute(New collection("--channel-binding=none"; "whoami"))
$report.shortOverride:=$explicit.execute(New collection("-Msimple"; "whoami"))
$report.tlsDowngrade:=cs.ldap.LDAP.new(New object("authMode"; "explicit"; "user"; "alice@CORP.EXAMPLE"; "password"; "x"; "tls"; "none")).whoami()
$report.authRejected:=New collection
For each ($options; New collection(\
	New object("authMode"; "explicit"; "user"; "alice@CORP.EXAMPLE"); \
	New object("authMode"; "explicit"; "password"; "x"); \
	New object("authMode"; "explicit"; "user"; "CORP\\alice"; "password"; "x"); \
	New object("authMode"; "explicit"; "user"; "alice@CORP.EXAMPLE"; "password"; "x"; "mech"; "simple"); \
	New object("authMode"; "explicit"; "user"; "alice@CORP.EXAMPLE"; "password"; "x"; "insecureSkipVerify"; True); \
	New object("authMode"; "explicit"; "user"; "alice@CORP.EXAMPLE"; "password"; "x"; "ccache"; "shared-cache"); \
	New object("authMode"; "sso"; "mech"; "gssapi"; "password"; "x"); \
	New object("authMode"; 123)))
	$report.authRejected.push(cs.ldap.LDAP.new($options).whoami())
End for each
$report.ssoPolicy:=cs.ldap.LDAP.new(New object("authMode"; "sso"; "mech"; "gssapi"; "channelBinding"; "require"))._authentication()
$report.capabilityRejected:=New collection
For each ($name; New collection("not json"; "[]"; "{\"schema\":\"1\",\"features\":[]}"; "{\"schema\":2,\"features\":[]}"; "{\"schema\":1,\"features\":\"wrong\"}"; "{\"schema\":1,\"features\":[123]}"; "{\"schema\":1,\"features\":[\"channel-binding-require\"]}"; "{\"schema\":1,\"features\":[\"CHANNEL-BINDING-REQUIRE\",\"explicit-credentials-sasl\"]}"))
	$capability:=New object("ok"; True; "stdout"; $name; "stderr"; ""; "exitCode"; 0)
	$report.capabilityRejected.push($explicit._checkCapabilities($capability; True))
End for each
$capability:=New object("ok"; True; "stdout"; "{\"schema\":1,\"features\":[\"explicit-credentials-sasl\",\"channel-binding-require\"]}"; "stderr"; ""; "exitCode"; 0)
$report.capabilityAccepted:=$explicit._checkCapabilities($capability; True).ok
$capability:=New object("ok"; True; "stdout"; "{\"schema\":1,\"features\":[\"channel-binding-require\"]}"; "stderr"; ""; "exitCode"; 0)
$report.ssoCapabilityAccepted:=$explicit._checkCapabilities($capability; False).ok
$capability:=New object("ok"; False; "stdout"; ""; "stderr"; "unknown command: capabilities"; "exitCode"; 2; "error"; New object("code"; "cli_error"; "message"; "unknown command: capabilities"))
$report.unsupportedCapability:=$explicit._checkCapabilities($capability; True)
HOST_Phase:="drop-in replacements"
// Component errors reach the host handler installed with ek errors from components,
// not the ek local one (with only a local handler the calling method is aborted).
HOST_Errors:=Null
HOST_ErrorScope:=""
ON ERR CALL("Host_capture"; ek local)
ON ERR CALL("Host_capture_component"; ek errors from components)
$ignoredObject:=LDAP_Search("DC=corp"; "(cn=x)")
$report.notLoggedIn:=New object("scope"; HOST_ErrorScope; "errors"; HOST_Errors)
HOST_Errors:=Null
HOST_ErrorScope:=""
LDAP_LOGIN("ldaps://127.0.0.1:1"; "cn=a"; "s3cret")
$report.loginFailed:=New object("scope"; HOST_ErrorScope; "errors"; HOST_Errors)
$report.sessionAfterFailure:=(LDAP_Session()#Null)
HOST_Errors:=Null
$options:=New object("authMode"; "explicit")
LDAP_SET_OPTIONS($options)
$options.authMode:="sso"
LDAP_LOGIN("ldaps://127.0.0.1:1"; "alice@CORP.EXAMPLE"; "")
$report.explicitMissingPassword:=New object("errors"; HOST_Errors)
HOST_Errors:=Null
LDAP_LOGIN("ldaps://127.0.0.1:1"; ""; "alice-secret")
$report.explicitMissingUser:=New object("errors"; HOST_Errors)
HOST_Errors:=Null
LDAP_LOGIN("ldaps://127.0.0.1:1"; "alice@CORP.EXAMPLE"; "alice-secret")
$report.explicitLoginGate:=New object("errors"; HOST_Errors)
$report.explicitSessionAfterFailure:=(LDAP_Session()#Null)
HOST_Errors:=Null
LDAP_SET_OPTIONS(New object("mech"; "gssapi"))
LDAP_LOGIN("ldaps://127.0.0.1:1"; "alice@CORP.EXAMPLE"; "alice-secret")
$report.saslPasswordLogin:=New object("errors"; HOST_Errors)
HOST_Errors:=Null
LDAP_SET_OPTIONS(New object("mech"; "gssapi"; "channelBinding"; "require"))
LDAP_LOGIN("ldaps://127.0.0.1:1"; "alice@CORP.EXAMPLE"; "")
$report.strictMissingPassword:=New object("errors"; HOST_Errors)
HOST_Errors:=Null
LDAP_SET_OPTIONS(New object("authMode"; "sso"; "mech"; "gssapi"))
LDAP_LOGIN("ldaps://127.0.0.1:1"; "alice@CORP.EXAMPLE"; "alice-secret")
$report.ssoCredentialsRejected:=New object("errors"; HOST_Errors)
HOST_Errors:=Null
LDAP_SET_OPTIONS(New object("authMode"; "explicit"; "bindDN"; "CN=service"))
LDAP_LOGIN("ldaps://127.0.0.1:1"; "alice@CORP.EXAMPLE"; "alice-secret")
$report.identityOverrideRejected:=New object("errors"; HOST_Errors)
HOST_Errors:=Null
LDAP_SET_OPTIONS(New object("mech"; 123))
LDAP_LOGIN("ldaps://127.0.0.1:1"; "alice@CORP.EXAMPLE"; "alice-secret")
$report.invalidMechanismType:=New object("errors"; HOST_Errors)
LDAP_SET_OPTIONS(Null)
HOST_Errors:=Null
ON ERR CALL(""; ek errors from components)
ON ERR CALL("Host_error"; ek local)
HOST_Phase:="missing executable"
$result:=cs.ldap._CLI.new("missing-cli"; $target).execute(New collection("--version"))
$report.missing:=$result
If ($result.error.code#"missing_executable")
	$report.success:=False
End if
$result:=cs.ldap.LDAP.new(New object("target"; "unsupported-arm-target")).version()
$report.unsupported:=$result
If ($result.error.code#"unsupported_architecture")
	$report.success:=False
End if
HOST_Phase:="launch failure"
$result:=cs.ldap._Process.new().execute($requestFile; New collection)
$report.launch:=$result
If ($result.error.code#"launch_failed")
	$report.success:=False
End if
HOST_Phase:="File argument"
$result:=cs.ldap._CLI.new("ldap"; $target).execute(New collection("escape"; "filter"; $requestFile))
$report.fileArgument:=$result
If (Not($result.ok))
	$report.success:=False
Else
	If ($result.stdout#(Host_filter_escape($parameter)+"\n"))
		$report.success:=False
	End if
End if
$report.rejectedArguments:=New collection
HOST_Phase:="scalar arguments"
For each ($invalid; New collection(123; 1.25; True; False; Null; Current date; Current time; New collection; New object))
	$result:=cs.ldap._Process.new().execute($requestFile; New collection($invalid))
	$report.rejectedArguments.push(New object("type"; Value type($invalid); "result"; $result))
	If ($result.ok | ($result.error.code#"invalid_argument"))
		$report.success:=False
	End if
End for each
$report.rejectedNul:=New collection
HOST_Phase:="NUL arguments"
For each ($name; New collection(Char(0)+"prefix"; "middle"+Char(0)+"suffix"; "trailing"+Char(0)))
	$result:=cs.ldap._Process.new().execute($requestFile; New collection($name))
	$report.rejectedNul.push($result)
	If ($result.ok | ($result.error.code#"invalid_argument"))
		$report.success:=False
	End if
End for each
$report.missingFile:=cs.ldap._Process.new().execute(Null; New collection)
$report.missingArguments:=cs.ldap._Process.new().execute($requestFile; Null)
If ($report.missingFile.ok | ($report.missingFile.error.code#"invalid_argument"))
	$report.success:=False
End if
If ($report.missingArguments.ok | ($report.missingArguments.error.code#"invalid_argument"))
	$report.success:=False
End if
HOST_Phase:="Folder argument"
$result:=cs.ldap._CLI.new("ldap"; $target).execute(New collection("escape"; "filter"; $requestFile.parent))
$report.folderArgument:=$result
$folderPath:=$requestFile.parent.path
If (Is Windows)
	$folderPath:=$requestFile.parent.platformPath
End if
If (Not($result.ok))
	$report.success:=False
Else
	If ($result.stdout#(Host_filter_escape($folderPath)+"\n"))
		$report.success:=False
	End if
End if
$report.finished:=True
ON ERR CALL(HOST_PreviousHandler; ek local)
$statusFile.setText(JSON Stringify($report))
HOST_StatusFile:=Null
HOST_Phase:=""
HOST_PreviousHandler:=""
QUIT 4D

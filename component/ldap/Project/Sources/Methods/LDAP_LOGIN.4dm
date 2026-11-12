//%attributes = {"shared":true,"preemptive":"capable"}
// Drop-in replacement for LDAP LOGIN(url; login; password{; digest})
//
// Differences that make it safer (see Documentation/Migration.md):
// - ldap:// upgrades to StartTLS; plaintext binds are refused, never sent.
// - The password is piped to the ldap process, never put on a command line.
// - digest is accepted for compatibility; DIGEST-MD5 (obsolete, RFC 6331) is not
//   used. Options select simple/TLS, explicit SASL/CBT or intentional SSO.
// - An empty password is anonymous only in compatibility simple-bind mode.
#DECLARE($url : Text; $login : Text; $password : Text; $digest : Integer)
var ldap_Current : Object  // cs.LDAP (process variables take no class type)
var ldap_Options : Object
var $connection : Object
var $session : cs.LDAP
var $result : Object
var $explicit : Boolean
ldap_Current:=Null
$connection:=(ldap_Options=Null) ? New object : OB Copy(ldap_Options)
Case of
	: ($url#"")
		$connection.uri:=$url
	: ((Value type($connection.uri)=Is null) & (Value type($connection.domain)=Is null))
		throw(New object("errCode"; 89; "message"; "LDAP_LOGIN: an empty url needs a domain: call LDAP_SET_OPTIONS({domain: \"corp.example\"}) first"; "componentSignature"; "ldap"))
		return
End case
$explicit:=($connection.authMode="explicit") | (($connection.channelBinding="require") & ($connection.authMode#"sso")) | (($password#"") & ($connection.mech#Null) & ($connection.mech#"simple"))
Case of
	: ($connection.authMode="sso")
		If (($login#"") | ($password#""))
			cs._Compat.new().raise(New object("ok"; False; "error"; New object("code"; "usage"; "message"; "LDAP_LOGIN: SSO requires empty login and password")))
			return
		End if
	: ($explicit)
		$connection.authMode:="explicit"
		$connection.user:=$login
		$connection.password:=$password
		OB REMOVE($connection; "bindDN")
	: ($password#"")
		$connection.mech:="simple"
		$connection.bindDN:=$login
		$connection.password:=$password
	: ((Value type($connection.mech)=Is text) && ($connection.mech#"simple"))
		// Legacy explicitly configured Kerberos / certificate binds need no password
	Else
		$connection.mech:="anonymous"
End case
$session:=cs.LDAP.new($connection)
// Bind now so that bad credentials fail here, like the built-in command.
If ($session.connection.channelBinding="require")
	// Explicit empty base selects RootDSE; no paging or optional Who Am I support is needed.
	$result:=$session.execute(New collection("--format=json"; "search"; "--base="; "--filter=(objectClass=*)"; "--scope=base"; "--size-limit=1"; "--page-size=0"; "--"; "1.1"))
Else
	$result:=$session.whoami()
End if
If ((Not($result.ok)) && ($result.error.code="ldap") && ($result.error.resultCode=2) && ($session.connection.channelBinding#"require"))
	$result.ok:=True  // server without the Who am I? extended operation: the bind itself succeeded
End if
If ($result.ok)
	ldap_Current:=$session
Else
	cs._Compat.new().raise($result)
End if

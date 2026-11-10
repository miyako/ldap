//%attributes = {"shared":true,"preemptive":"capable"}
// Drop-in replacement for LDAP LOGIN(url; login; password{; digest})
//
// Differences that make it safer (see Documentation/Migration.md):
// - ldap:// upgrades to StartTLS; plaintext binds are refused, never sent.
// - The password is piped to the ldap process, never put on a command line.
// - digest is accepted for compatibility; DIGEST-MD5 (obsolete, RFC 6331) is not
//   used: both values perform a simple bind inside TLS.
// - An empty password means an anonymous bind, as with the built-in command.
#DECLARE($url : Text; $login : Text; $password : Text; $digest : Integer)
var ldap_Current : Object  // cs.LDAP (process variables take no class type)
var ldap_Options : Object
var $connection : Object
var $session : cs.LDAP
var $result : Object
ldap_Current:=Null
$connection:=(ldap_Options=Null) ? New object : OB Copy(ldap_Options)
Case of
	: ($url#"")
		$connection.uri:=$url
	: ((Value type($connection.uri)=Is null) & (Value type($connection.domain)=Is null))
		throw(New object("errCode"; 89; "message"; "LDAP_LOGIN: an empty url needs a domain: call LDAP_SET_OPTIONS({domain: \"corp.example\"}) first"; "componentSignature"; "ldap"))
		return
End case
Case of
	: ($password#"")
		$connection.mech:="simple"
		$connection.bindDN:=$login
		$connection.password:=$password
	: ((Value type($connection.mech)=Is text) && ($connection.mech#"simple"))
		// Kerberos / certificate binds configured with LDAP_SET_OPTIONS need no password
	Else
		$connection.mech:="anonymous"
End case
$session:=cs.LDAP.new($connection)
// Bind now so that bad credentials fail here, like the built-in command.
$result:=$session.whoami()
If ((Not($result.ok)) && ($result.error.code="ldap") && ($result.error.resultCode=2))
	$result.ok:=True  // server without the Who am I? extended operation: the bind itself succeeded
End if
If ($result.ok)
	ldap_Current:=$session
Else
	cs._Compat.new().raise($result)
End if

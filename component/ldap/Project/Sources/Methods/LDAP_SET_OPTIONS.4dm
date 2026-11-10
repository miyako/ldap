//%attributes = {"shared":true,"preemptive":"capable"}
// Connection options for the next LDAP_LOGIN in this process, e.g.
// LDAP_SET_OPTIONS({caCert: $pem; tlsServerName: "dc1.corp.example"; operationTimeout: 30})
// LDAP_SET_OPTIONS({domain: "corp.example"; mech: "gssapi"}) then LDAP_LOGIN(""; ""; "") for Kerberos SSO.
// Accepts every cs.ldap.LDAP connection property except password.
#DECLARE($options : Object)
var ldap_Options : Object
ldap_Options:=($options=Null) ? Null : OB Copy($options)
If (ldap_Options#Null)
	OB REMOVE(ldap_Options; "password")
End if

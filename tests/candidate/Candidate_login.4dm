//%attributes = {"invisible":true}
#DECLARE($config : Object)->$report : Object
var HOST_Errors : Collection
var $options : Object
var $session : cs.ldap.LDAP
HOST_Errors:=Null
ON ERR CALL("Host_capture_component"; ek errors from components)
$options:=New object("authMode"; "explicit"; "connectTimeout"; 3; "operationTimeout"; 5; "processTimeout"; 15)
If ($config.caCert#Null)
	$options.caCert:=$config.caCert
End if
If ($config.tlsServerName#Null)
	$options.tlsServerName:=$config.tlsServerName
End if
LDAP_SET_OPTIONS($options)
LDAP_LOGIN($config.uri; $config.user; $config.password)
$report:=New object("errors"; HOST_Errors; "sessionPresent"; False)
$session:=LDAP_Session()
If ($session#Null)
	$report.sessionPresent:=True
	$report.user:=$session.connection.user
	$report.whoami:=$session.whoami()
	$report.entry:=LDAP_Search($config.base; "(uid="+$config.uid+")"; "sub"; New collection("uid"))
End if
LDAP_LOGOUT
LDAP_SET_OPTIONS(Null)
ON ERR CALL(""; ek errors from components)

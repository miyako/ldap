//%attributes = {"invisible":true}
#DECLARE()->$report : Object
var $config; $a; $b; $invalid : Object
var $fileA; $fileB : 4D.File
var $attempt : Integer
var $session : cs.ldap.LDAP
var HOST_Errors : Collection
$config:=JSON Parse(File("/RESOURCES/candidate.json").getText())
$a:=New object("uri"; $config.uri; "caCert"; $config.caCert; "base"; $config.base; "user"; $config.userA; "password"; $config.passwordA; "uid"; "alice")
$b:=New object("uri"; $config.uri; "caCert"; $config.caCert; "base"; $config.base; "user"; $config.userB; "password"; $config.passwordB; "uid"; "bob")
$report:=New object("alice"; Candidate_login($a); "bob"; Candidate_login($b))
$invalid:=OB Copy($b)
$invalid.password:="incorrect-test-password"
$report.wrongPassword:=Candidate_login($invalid)
$invalid:=OB Copy($b)
$invalid.password:=""
$report.missingPassword:=Candidate_login($invalid)
$invalid:=OB Copy($b)
OB REMOVE($invalid; "caCert")
$report.untrustedTLS:=Candidate_login($invalid)
$invalid:=OB Copy($b)
$invalid.tlsServerName:="wrong.invalid"
$report.wrongHostname:=Candidate_login($invalid)
HOST_Errors:=Null
ON ERR CALL("Host_capture_component"; ek errors from components)
LDAP_SET_OPTIONS(New object("authMode"; "explicit"; "caCert"; $config.caCert; "connectTimeout"; 3; "operationTimeout"; 5; "processTimeout"; 15))
LDAP_LOGIN($a.uri; $a.user; $a.password)
$report.mainLoginErrors:=HOST_Errors
$fileA:=File("/RESOURCES/candidate.json").parent.file("worker-a.json")
$fileB:=File("/RESOURCES/candidate.json").parent.file("worker-b.json")
CALL WORKER("Candidate Alice"; "Candidate_worker"; $a; $fileA.platformPath)
CALL WORKER("Candidate Bob"; "Candidate_worker"; $b; $fileB.platformPath)
For ($attempt; 1; 600)
	If ($fileA.exists & $fileB.exists)
		break
	End if
	DELAY PROCESS(Current process; 6)
End for
$report.workersFinished:=$fileA.exists & $fileB.exists
If ($report.workersFinished)
	$report.workerAlice:=JSON Parse($fileA.getText())
	$report.workerBob:=JSON Parse($fileB.getText())
End if
$session:=LDAP_Session()
If ($session#Null)
	$report.mainUserAfterWorkers:=$session.connection.user
	$report.mainIdentityAfterWorkers:=$session.whoami()
End if
$invalid:=OB Copy($b)
$invalid.password:="incorrect-test-password"
$report.replacementWrongPassword:=Candidate_login($invalid)
LDAP_LOGOUT
LDAP_SET_OPTIONS(Null)
ON ERR CALL(""; ek errors from components)

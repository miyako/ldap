//%attributes = {"invisible":true}
#DECLARE($config : Object; $statusPath : Text)
var $report : Object
$report:=Candidate_login($config)
File($statusPath; fk platform path).setText(JSON Stringify($report))

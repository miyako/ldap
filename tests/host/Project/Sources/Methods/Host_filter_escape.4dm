//%attributes = {"invisible":true}
// Reference RFC 4515 value escaping, to check the CLI's output independently.
#DECLARE($value : Text)->$escaped : Text
$escaped:=Replace string($value; "\\"; "\\5c"; *)
$escaped:=Replace string($escaped; "*"; "\\2a"; *)
$escaped:=Replace string($escaped; "("; "\\28"; *)
$escaped:=Replace string($escaped; ")"; "\\29"; *)

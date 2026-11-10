//%attributes = {"shared":true,"preemptive":"capable"}
// Drop-in replacement for LDAP SEARCH ALL(dnRootEntry; arrResult; filter{; scope{; attributes{; attributesAsArray}}})
// arrResult: pointer to an Object array (->arrResult) or a Collection to fill.
// Results are paged, so the server's size limit (AD: 1000) does not truncate them.
#DECLARE($dnRootEntry : Text; $result : Variant; $filter : Text; $scope : Text; $attributes : Variant; $attributesAsArray : Variant)
var $entries : Collection
var $entry : Object
$entries:=cs._Compat.new().search($dnRootEntry; $filter; $scope; $attributes; $attributesAsArray)
Case of
	: (Value type($result)=Is pointer)
		ARRAY OBJECT($result->; 0)
		For each ($entry; $entries)
			APPEND TO ARRAY($result->; $entry)
		End for each
	: (Value type($result)=Is collection)
		$result.clear()
		$result.combine($entries)
End case

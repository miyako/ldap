//%attributes = {"shared":true,"preemptive":"capable"}
// Drop-in replacement for LDAP Search(dnRootEntry; filter{; scope{; attributes{; attributesAsArray}}}) : Object
// attributes / attributesAsArray: pass array pointers (->arrAttributes) or Collections.
#DECLARE($dnRootEntry : Text; $filter : Text; $scope : Text; $attributes : Variant; $attributesAsArray : Variant)->$entry : Object
var $entries : Collection
$entries:=cs._Compat.new().search($dnRootEntry; $filter; $scope; $attributes; $attributesAsArray)
$entry:=($entries.length>0) ? $entries[0] : New object

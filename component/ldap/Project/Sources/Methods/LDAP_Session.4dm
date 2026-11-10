//%attributes = {"shared":true,"preemptive":"capable"}
// The cs.ldap.LDAP instance opened by LDAP_LOGIN in this process (Null if none).
// Lets migrated code mix legacy calls with the full API: add, modify, delete, rename,
// compare, changePassword, templates, paging, sort, controls…
#DECLARE()->$session : cs.LDAP
var ldap_Current : Object  // cs.LDAP (process variables take no class type)
$session:=ldap_Current

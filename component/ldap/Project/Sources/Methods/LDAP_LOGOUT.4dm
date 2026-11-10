//%attributes = {"shared":true,"preemptive":"capable"}
// Drop-in replacement for LDAP LOGOUT
// No network connection is held between calls, so this only forgets the
// credentials stored for the current process.
var ldap_Current : Object  // cs.LDAP (process variables take no class type)
ldap_Current:=Null

# LDAP_LOGOUT

`LDAP_LOGOUT`

Drop-in replacement for the built-in `LDAP LOGOUT`. No network connection stays
open between calls, so this forgets the session stored for the current process.

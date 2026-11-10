# LDAP_SEARCH_ALL

`LDAP_SEARCH_ALL(dnRootEntry : Text; arrResult; filter : Text {; scope : Text {; attributes {; attributesAsArray}}})`

Drop-in replacement for the built-in `LDAP SEARCH ALL`. `arrResult` is a pointer
to an Object array (`->$_entry`) or a Collection, filled with one object per
entry, shaped as described in [LDAP_Search](LDAP_Search.md).

Searches are paged, so the server's size limit (1000 entries by default on
Active Directory) no longer truncates the result.

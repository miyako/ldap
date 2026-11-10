# LDAP_Search

`LDAP_Search(dnRootEntry : Text; filter : Text {; scope : Text {; attributes {; attributesAsArray}}}) : Object`

Drop-in replacement for the built-in `LDAP Search`. Returns the attributes of the
first matching entry, shaped like the built-in result: one value gives a scalar,
several give a Collection; `attributesAsArray` True forces a Collection, False
forces the first value. Requested attribute names are returned with your spelling.

`attributes` and `attributesAsArray` take array **pointers** (`->arrAttributes`,
`->arrAsArray`) or Collections. `scope` defaults to `"base"`, like the built-in
command; the `LDAP root only`, `LDAP root and next` and `LDAP all levels`
constants still work.

`dnRootEntry` and `filter` are used literally: braces are escaped, so they are not
templates. The filter is syntax-checked before it is sent.

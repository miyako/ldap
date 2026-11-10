// Internal helpers for the LDAP_* drop-in replacements of the built-in LDAP theme.
// Session state lives in component process variables, so (like the built-ins)
// a login is scoped to the current process and never leaks to another one.

Function session()->$session : cs.LDAP
	var ldap_Current : Object  // cs.LDAP (process variables take no class type)
	If (ldap_Current=Null)
		throw(New object("errCode"; 1003; "message"; "No LDAP connection: call LDAP_LOGIN first"; "componentSignature"; "ldap"))
	End if
	$session:=ldap_Current
	
Function raise($result : Object)
	// Turn a failed result into a 4D error, as the built-in commands do.
	// errCode follows libldap: the LDAP result code, 49 for a failed bind,
	// 81 (server down) for connection/TLS failures, 89 (param error) for usage errors.
	var $code : Integer
	If ($result.ok)
		return
	End if
	Case of
		: ($result.error.code="ldap")
			$code:=$result.error.resultCode
		: ($result.error.code="authentication")
			$code:=49
		: ($result.error.code="connection")
			$code:=81
		: ($result.error.code="usage")
			$code:=89
		Else
			$code:=-1
	End case
	throw(New object("errCode"; $code; "message"; String($result.error.message); "componentSignature"; "ldap"))
	
Function literal($text : Text)->$template : Text
	// Built-in filters and DNs are literal text: neutralise template braces.
	$template:=Replace string(Replace string($text; "{"; "{{"; *); "}"; "}}"; *)
	
Function list($value : Variant)->$list : Collection
	// Text/Boolean array pointer (legacy call sites) or Collection (modern ones)
	$list:=New collection
	Case of
		: (Value type($value)=Is collection)
			$list:=$value
		: (Value type($value)=Is pointer)
			If (Not(Is nil pointer($value)))
				ARRAY TO COLLECTION($list; $value->)
			End if
	End case
	
Function search($base : Text; $filter : Text; $scope : Text; $attributes : Variant; $asArray : Variant)->$entries : Collection
	var $session : cs.LDAP
	var $options : Object
	var $result : Object
	var $entry : Object
	$entries:=New collection
	// After a 4D error handler returns, execution resumes on the next line:
	// every throw below is followed by an explicit return.
	$session:=This.session()
	If ($session=Null)
		return
	End if
	$options:=New object("scope"; ($scope="") ? "base" : $scope)
	$options.names:=This.list($attributes)
	$options.forced:=This.list($asArray)
	If ($options.names.length>0)
		$options.attributes:=$options.names
	End if
	$result:=$session.search(This.literal($base); ($filter="") ? "(objectClass=*)" : This.literal($filter); $options)
	If (Not($result.ok))
		This.raise($result)
		return
	End if
	For each ($entry; $result.entries)
		$entries.push(This.shape($entry; $options.names; $options.forced))
	End for each
	
Function shape($entry : Object; $names : Collection; $forced : Collection)->$shaped : Object
	// Built-in result shape: one value → scalar, several → collection;
	// attributesAsArray True forces a collection, False forces the first value.
	// Requested names are returned with the caller's spelling.
	var $key; $name : Text
	var $index : Integer
	var $values : Collection
	$shaped:=New object
	For each ($key; $entry.attributes)
		$name:=$key
		$index:=$names.findIndex(Formula($1.result:=($1.value=$2)); $key)  // 4D Text comparison ignores case
		If ($index>=0)
			$name:=$names[$index]
		End if
		$values:=$entry.attributes[$key]
		Case of
			: (($index>=0) && ($index<$forced.length) && ($forced[$index]=True))
				$shaped[$name]:=$values
			: (($index>=0) && ($index<$forced.length) && ($forced[$index]=False))
				$shaped[$name]:=$values[0]
			: ($values.length=1)
				$shaped[$name]:=$values[0]
			Else
				$shaped[$name]:=$values
		End case
	End for each

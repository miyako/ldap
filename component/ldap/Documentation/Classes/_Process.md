# _Process (internal convention)

This adapter launches a standalone executable through `4D.SystemWorker`; it is
not a native 4D plug-in loader. Features requiring native 4D SDK integration
belong to the separate host-installed plug-in architecture, not a private
component backend.

`cs._Process.new().execute(file : 4D.File; arguments : Collection {; settings : Object}) : Object`
is the generic synchronous process adapter. Arguments must be Text, File or
Folder. File/Folder values are expanded to physical POSIX paths on macOS or
platform paths on Windows; NUL is rejected using exact string comparison.
Numeric, Boolean, Null, date/time and Collection values are rejected before
object-instance checks; plain Objects are also rejected. They return
`invalid_argument`, rather than raising a 4D object-type error or launching a process.

`quote(argument : Text) : Text` always quotes one argument. macOS double quotes
escape backslashes and quotes; Windows follows the CRT backslash-before-quote
and trailing-backslash rules. This is 4D command-line parsing, not a shell.
The executable is a physical POSIX File path as required by SystemWorker.
Native 4D round-trip tests, not shell tests, are necessary on each platform.

Options: `dataType:"text"`, `encoding:"UTF-8"`, `hideWindow:true`,
`timeout:30`, `currentDirectory:file.parent`. Optional `settings`:
`timeout` (seconds, replaces 30) and `stdin` (Text written to the process's
standard input with `.postMessage()` before it is closed; this is how secrets
reach the CLI without appearing on its command line or in its environment).
Input is then closed and `.wait()` completes. The adapter captures `.response` (stdout),
`.responseError` (stderr), `.exitCode` and `.errors` separately.
Nonempty stderr does not turn a zero exit code into failure. Missing/undefined
exitCode is abnormal termination, not zero.

Creation errors use `_CaptureError` and restore `Method called on error(ek local)`
immediately afterward. Diagnostic `Last errors` are returned, not swallowed.
There is no shared async queue/PID map or global handler. For binary feature
protocols, add a deliberately separate Blob mode rather than corrupting UTF-8 text.

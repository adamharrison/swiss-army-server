# swiss-army-server

```
Usage: swiss-army-server [--lots-of-flags]

swiss-army-server is a simple webserver, that can serve static content,
or point upstream. It's designed to be really flexible, and extensible,
and really easy to modify the internals, unlike some others (I'm looking
at you nginx!), while providing a bunch of common functionality out of
the box.

It's also aiming to be fast and *simple* and extremely extensible.

Not insanely fast, but fast enough for pretty much any out of the box
purpose. Certainly faster than pretty much any application server. It's
basically designed to be a CLI server swiss-army knife in very little code
designed for linux specifically.

It's simple, in that it's two files, and optionally statically linked. 
It should work on pretty much any mac/linux machine with no hassle, no
setup, and a near instantaneous compile time with no build depedencies.
It has a very clean API, with very little extraneous calls that hopefully 
"does what you want" without having to think about it much. It specifically
doesn't require a config file; everything can be done with command line 
switches, though you can have one if it makes you happy.

It's extensible via lua's normal `require` mechanism, allowing you to add
lua code, or native code (by compiling a native lua module).

There aren't that many flags, but they're highly context sensitive. 
**The order of server and location flags matters quite a lot**, so pay 
attention to exactly how they're laid out.

General Flags

  --help              Displays this help text.
  --version           Displays the version (]] .. VERSION .. [[).
  --plugin=path       Loads the specified plugin. Accepts wildcards.
  --server=0.0.0.0:80 Denotes a server socket, listening on a port. 
                      All server flags affect the most recently
                      declared server. Listens on the specified address
                      and port, given in the form of 0.0.0.0:80. Accepts
                      a range of ports. If the port is not an integer,
                      listens on a unix socket at that location. If stdin
                      if specified, listens off STDIN.

Server Flags

  If no server has been specified, affects all servers, otherwise
  affects only the most recently specified server.
  
  --ssl_cert=path     Specifies the certificate path.
  --ssl_key=path      Specifies the private key.
  --ssl_callback=...  Specifies a literal lua function body to return 
                      [certificate, private_key], taking (hostname).
                      If it specifies a path, will load the lua file/shared
                      library at that location, and call it.
  --keep_alive=0      Specifies to keep connections alive, and if passed a
                      positive integer, uses as the timeout.
  --location=path     Specifies on the path to sit. All subsequent location
                      flags affect this path. Is a lua pattern. If it doesn't
                      start with `/`, then is treated as a named location
                      to be referenced by `error`. If no locations are ever
                      specified, `/` is implied as the default location for
                      everything.

Host Flags

  If no host has been specified, affects all hosts. Otherwise affects
  only the most recently specified host.

  --host=hostname    Specifies the hostname to listen for.

Location Flags

  If no location has been specified, affects all subsequent locations for
  this server. If no server has been specified affects all locations. Any
  string can specify an incoming all caps header value with the name 
  of the header preceded by a $ ($PATH). Query parameters can be specified
  with a % (%q). These can be escaped with backslash.

  --static=path       Statically serves content located at the path, if
                      the path specified is a directory. If it's a file
                      serves that file.
  --forward=host:port Forwards the HTTP request onto the specified location.
  --timeout=60        Sets the timeout for activity on this location.
  --code=200          Specifies a manual response code.
  --header=name:val   Specifies a response header. If after a `forward`
                      or if no forward present, adds the header to the response.
                      If before a `forward`, adds the header to the forwarded
                      request. If `:val` is omitted, removes the header.
  --body=string       Specifies a manual response body.
  --callback=...      Specifies a literal lua function body to return 
                      [code, header, body], taking (headers, body).
                      If it specifies a path, will load the lua file/shared
                      library at that location, and call it.
                      that location, and use that.
  --error=...         Specifies a location where errors are to be routed.
                      If specifies as a comma separated list of numbers, 
                      followed by a colon, then the location, only routes
                      those specifies errors. If the location is a path,
                      will use that path and serve the file there.
  --std[out|err]=...  Logs to the specified file. Specify /dev/null
                      to discard.
  --compress=deflate  Compresses all responses with DEFLATE encoding. 
                      Adds appropriate header.
  --inherit=location  Specifies that we should inherit all settings from
                      the specified location and override.
  --redirect=url      A quick way of specying a 302. 
  --verbose           Dumps requests and responses to STDOUT.
  --gnu               Adds 'X-Clacks-Overhead: GNU Terry Pratchett' header.
  --[get|post|...]    Limits interactions to only these methods.

```

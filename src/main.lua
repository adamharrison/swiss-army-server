local function parse_arguments(arguments, options, start_index, end_index)
  local args = {}
  local i = start_index
  end_index = end_index or #arguments
  while i <= end_index do
    local s,e, option, value = arguments[i]:find("%-%-([^=]+)=?(.*)")
    if s then
      local flag_type = options[option]
      if not flag_type then error("unknown flag --" .. option) end
      if flag_type == "flag" then
        args[option] = true
      elseif flag_type == "string" or flag_type == "number" then
        if not value then
          if i < #arguments then error("option " .. option .. " requires a " .. flag_type) end
          value = arguments[i+1]
          i = i + 1
        end
        if flag_type == "number" and tonumber(flag_type) == nil then error("option " .. option .. " should be a number") end
        args[option] = value
      end
    else
      table.insert(args, arguments[i])
    end
    i = i + 1
  end
  return args
end


xpcall(function()
  local ARGS = parse_arguments(ARGV, { 
    plugin = "list"
  })
  if ARGS["version"] then
    io.stdout:write(VERSION .. "\n")
    return 0
  end
  if ARGS["help"] or #ARGS == 1 or ARGS[2] == "help" then
    io.stderr:write([[
Usage: swiss-army-server 

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

Flags have the following effects:

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
  --location=/        Specifies on the path to sit. All subsequent location
                      flags affect this path. Is a lua pattern. If it doesn't
                      start with `/`, then is treated as a named location
                      to be referenced by `error`.
  --keep-alive=0      Specifies to keep connections alive, and if passed a
                      positive integer, uses as the timeout.

  Location Flags

  If no location has been specified, affects all subsequent locations for
  this server. If no server has been specified affects all locations. Any
  string can specify an incoming header value with the name of the header
  preceded by a $ ($PATH).

  --static=path       Statically serves content located at the path, if
                      the path specified is a directory. If it's a file
                      serves that file.
  --forward=host:port Forwards the HTTP request onto the specified location.
  --timeout=60        Sets the timeout for activity on this location.
  --code=200          Specifies a manual response code.
  --header=name:val   Specifies a response header.
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
  --deflate           Compresses all responses with DEFLATE encoding. 
                      Adds appropiate header.
  --verbose           Dumps requests and responses to STDOUT.
              
  
]]
    )
    return 0
  end

  for i,v in ipairs(ARGV) 
  
end, error_handler)


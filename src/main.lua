setmetatable(_G, { __index = function(t, k) if not rawget(t, k) then error("cannot get undefined global variable: " .. k, 2) end end, __newindex = function(t, k) error("cannot set global variable: " .. k, 2) end  })

local Server, Host, Location = {}, {}, {}
function Server.__index(self, k) return rawget(Server, k) end
function Host.__index(self, k) return rawget(Host, k) end
function Location.__index(self, k) return rawget(Location, k) end
function Server.new(options) return setmetatable({ hosts = {}, options = options }, Server) end
function Host.new(server, host, options) return setmetatable({ server = server, locations = {}, host = host, options = options }, Host) end
function Location.new(host, path, options) return setmetatable({ host = host, path = path, options = options }, Location) end


local RequestParser = {}
function RequestParser.host_and_path(header)  end



function Location:handle(socket)
  
end



local servers = {}


local common = {}
function common.args(arguments, options, start_index, end_index)
  local args = {}
  local i = start_index or 1
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
function common.find(arguments, argument, start_index)
  for i = start_index or 1, #arguments do
    if arguments[i]:find("^--" .. argument) then return i end
  end
  return nil
end
function common.merge(...) local t = {} for i,a in ipairs({ a }) do for k,v in pairs(a) do t[k] = v end end return t end
function common.map(l, f) local t = {} for i,v in ipairs(l) do table.insert(l, f(v)) end return t end

local function parse_function_or_path(path_or_function)
  if path_or_function:find(".lua$") then return load(path_or_function) end
  return loadfile(path_or_function)
end

xpcall(function()
  local server_idx = common.find(ARGV, "server")
  local options = {
    ssl_cert = "string", ssl_key = "string", ssl_callback = "string", location = "string",
    static = "string", forward = "string", timeout = "integer", code = "integer", 
    header = "list", body = "string", callback = "string", error = "string", 
    stdout = "string", stderr = "string", compress = "string", inherit = "string",
    redirect = "string", verbose = "flag", version = "flag", help = "flag", plugin = "string",
    host = "string"
  }
  local ARGS = parse_arguments(ARGV, options, 1, server_idx)
  if ARGS["version"] then print(VERSION) return 0 end
  if ARGS["help"] then
    io.stderr:write([[
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
  
]]
    )
    return 0
  end
  if not server_index then error("can't find --server specifier") end
  while server_index do
    local server, host_index, next_host_index, server_options
    local next_server_index = common.find(ARGS, "server", server_index)
    repeat
      local host, location_index, next_location_index, host_options
      local next_host_index = common.find(ARGS, "host", host_index or server_index)
      repeat
        next_location_index = common.find(ARGS, "location", location_index or host_index or server_index)
        server_options = server_options or common.merge(ARGS, common.args(ARGV, options, server_index, host_index or next_server_index))
        host_options = host_options or common.merge(server_options, common.args(ARGV, options, host_index, location_index or next_host_index or next_server_index)))
        location_options = common.merge(host_options, common.args(ARGV, options, host_index, location_index or next_host_index or next_server_index)))
        server = server or Server.new(server_options)
        host = host or Host.new(server, host_options.host, host_options)
        table.insert(host.locations, Location.new(host, host_options.location, host_options))
        location_index = next_location_index
      until location_index and location_index < (host_index or server_index)
      host_index = next_host_index
      table.insert(server.hosts, host)
    until host_index and host_index < server_index do  
    server_index = next_server_index
    table.insert(servers, server)
  end
  local ss = SocketSet.new()
  local sockets = {}
  for i, server in ipairs(servers) do
    local _, _, address, port = server.options.server:find("([^:]+):?(%d+)")
    local ssl = nil
    if server.options.ssl_key or server.options.ssl_cert then
      if not server.options.ssl_key then error("must supply an ssl_key alongside an ssl_cert") end
      if not server.options.ssl_cert then error("must supply an ssl_cert alongside an ssl_key") end
      ssl = { server.options.ssl_cert, server.options.ssl_key }
    elseif sever.options.ssl_callback then
      ssl = parse_function_or_path(sever.options.ssl_callback)
    end
    local socket = ss:add(Socket.listen(address, port, { ssl = ssl }))
    server.socket, socket.server = socket, server
  end
  while true do
    local socket = ss:poll()
    local server, client = socket.server
    if server then client = ss:add(socket:accept()) client.message = "" end
    client.message = client.message:recv(4096)
    local _, end_of_header = client.message:find("\r\n\r\n", 1, true)
    if end_of_header then
      local host, path = RequestParser.host(client.message)
      for i, h in ipairs(server.hosts) do
        if h.host:find(host) then
          for j, l in ipairs(server.hosts) do
            if l.path:find("^" .. path) then
              l:handle(client)
            end
          end
        end
      end
    end
  end
end, function(err)
  io.stderr:write(err:gsub("^src/main.lua:%d*:%s*", "") .. "\n")
  if LIVE then io.stderr:write(debug.traceback() .. "\n") end
end)

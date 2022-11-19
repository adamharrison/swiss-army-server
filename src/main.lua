setmetatable(_G, { __index = function(t, k) if not rawget(t, k) then error("cannot get undefined global variable: " .. k, 2) end end, __newindex = function(t, k) error("cannot set global variable: " .. k, 2) end  })

local LOCAL_IO_CHUNK_SIZE = 10*4096
local FORWARD_CHUNK_SIZE = 4096
local HEADER_CHUNK_SIZE = 4096
local MAX_HEADER_SIZE = 4096

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

local Request = {}
local Response = {}

local codes = {
  [100] = "Continue", [101] = "Switching Protocols", [102] = "Processing", [103] = "Early Hints",
  [200] = "OK", [201] = "Created", [202] = "Accepted", [203] = "Non-Authoritative Information", [204] = "No Content", [205] = "Reset Content", [206] = "Partial Content", [207] = "Multi-Status", [208] = "Already Reported", [226] = "IM Used",
  [300] = "Multiple Choices", [301] = "Moved Permanently", [302] = "Found", [303] = "See Other", [304] = "Not Modified", [305] = "Use Proxy", [306] = "Switch Proxy", [307] = "Temporary Redirect", [308] = "Permanent Redirect",
  [400] = "Bad Request", [401] = "Unauthorized", [402] = "Payment Required", [403] = "Forbidden", [404] = "Not Found", [405] = "Method Not Allowed", [406] = "Not Acceptable", [407] = "Proxy Authentication Required", [408] = "Request Timeout",
  [409] = "Conflict", [410] = "Gone", [411] = "Length Required", [412] = "Precondition Failed", [413] = "Payload Too Large", [414] = "URI Too Long", [415] = "Unsupported Media Type", [416] = "Range Not Satisfiable", [417] = "Expectation Failed",
  [418] = "I'm a Teapot", [421] = "Misdirected Request", [422] = "Unprocessable Entity", [423] = "Locked", [424] = "Failed Dependency", [425] = "Too Early", [426] = "Upgrade Required", [428] = "Precondition Required", [429] = "Too Many Requests",
  [431] = "Request Header Fields Too Large", [451] = "Unavailable For Legal Reasons",
  [500] = "Internal Server Error", [501] = "Not Implemented", [502] = "Bad Gateway", [503] = "Services Unavaialable", [504] = "Gateway Timeout", [505] = "HTTP Version Not Supported", [506] = "Variant Also Negotiates", [507] = "Insufficient Storage",
  [507] = "Insufficient Storage", [508] = "Loop Detected", [510] = "Not Extended", [511] = "Network Authentication Required"
}

function Request.parse(message)
  local headers = {}
  local start_of_header, end_of_header = message:find("\r\n\r\n", 1, true)
  local primary_line = message:find("\r\n")
  local method_end = message:find(" ")
  local path_end = message:find(" ", method_end + 1)
  local method = messge:sub(1, method_end - 1)
  local path = message:sub(method_end + 1, path_end - 1)
  local version = message:sub(path_end + 1)
  local offset = primary_line + 1
  while offset < start_of_header do
    local s,e = message:find(":%s*", offset)
    headers[message:sub(offset, s - 1):lower()] = message:sub(offset, e + 1)
    offset = message:find("\r\n", e + 1) + 1
  end
  return version, method, path, headers, message:sub(end_of_header+1)
end

function Request.write(socket, method, path, headers)
  socket:write(method .. " " .. path .. " HTTP/1.1")
  for k,v in ipairs(headers) do socket:write(k .. ": " .. v .. "\r\n") end
  socket:write("\r\n")
end

function Response.write(socket, code, headers)
  socket:write("HTTP/1.1 " .. code .. " " .. codes[code] .. "\r\n")
  for k,v in ipairs(headers) do socket:write(k .. ": " .. v .. "\r\n") end
  socket:write("\r\n")
end


local Server, Host, Location = {}, {}, {}
function Server.__index(self, k) return rawget(Server, k) end
function Host.__index(self, k) return rawget(Host, k) end
function Location.__index(self, k) return rawget(Location, k) end
function Server.new(options) return setmetatable({ hosts = {}, options = options }, Server) end
function Host.new(server, host, options) return setmetatable({ server = server, locations = {}, host = host, options = options }, Host) end
function Location.new(host, path, options) 
  local self = setmetatable({ host = host, path = path, options = options }, Location) 
  if options.gnu then self.options.headers["X-Clacks-Overhead"] = "GNU Terry Pratchett" end
  if options.redirect then self.options.headers["Location"] = options.location self.options.code = 302 end
  if options.get or options.post or options.put or options.delete then 
    self.options.methods = {}
    if options.get then self.options.methods["GET"] = true end
    if options.post then self.options.methods["POST"] = true end
    if options.put then self.options.methods["PUT"] = true end
    if options.delete then self.options.methods["DELETE"] = true end
  end
  return self
end


function Location:init(socket, method, path, headers)
  if self.options.static then
    local anchor = type(options.static) == "string" and options.static or "."
    local stat = system.stat(anchor)
    local target = stat.type == "dir" and (anchor .. PATHSEP .. truncated)  or anchor
    local fh = io.open(target, "rb")
    if not fh then error({ 404 }) end
    socket.static = { stat = stat, fh = fh }
    Response.write(socket, 200, common.merge(options.headers, { ["Content-Length"] = stat.size, ["Content-Type"] = getMimeType(target) }))
  elseif self.options.forward then
    local _, _, protocol, host, port = options.forward:find("^(%w+)://([^:]+):?(%d+)$")
    socket.forward = { client = Socket.connect(protocol, host, port), length = headers["Content-Length"] } -- this is blocking for now, may want to change this in future.
    Request.write(socket.forward.client, code, headers)
  elseif self.options.callback then
    self.options.callback(socket, method, path, headers)
  else
    local code = options.code or (options.body and 200 or 204)
    local headers = options.body and common.merge(options.headers, { ["Content-Length"] = #options.body }) or options.headers
    Response.writeHeaders(socket, code, headers)
  end
end


function Location:cont(socket, method, path, headers, body)
  if socket.static then
    local chunk = socket.static.fh:read(LOCAL_IO_CHUNK_SIZE)
    if not chunk then socket.static = nil return false end
    socket:write(chunk)
    return true
  end
  if socket.forward then
    local chunk = body
    if socket.forward.length then 
      chunk = socket:read(math.min(socket.forward.length, FORWARD_CHUNK_SIZE))
      socket.forward.length = socket.forward.length - #chunk
    else
      chunk = socket:read(FORWARD_CHUNK_SIZE)
      if not chunk then socket.forward.client:close() socket.forward = nil return false end
    end
    socket.forward.client:write(chunk)
    return true
  end
  if socket.callback then
    return socket.callback(socket, method, path, headers, body)
  end
  if socket.manual then
    if options.body then socket:write(options.body) end
    return false
  end
end



local servers = {}



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
    host = "string", gnu = "flag", get = "flag", post = "flag", put = "flag", delete = "flag"
  }
  local ARGS = common.args(ARGV, options, 1, server_idx)
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
  --gnu               Adds 'X-Clacks-Overhead: GNU Terry Pratchett' header.
  --[get|post|...]    Limits interactions to only these methods.
  
]]
    )
    return 0
  end
  if not server_idx then error("can't find --server specifier") end
  while server_idx do
    local server, host_idx, next_host_idx, server_options
    local next_server_idx = common.find(ARGS, "server", server_idx)
    repeat
      local host, location_idx, next_location_idx, host_options
      local next_host_idx = common.find(ARGS, "host", host_idx or server_idx)
      repeat
        next_location_idx = common.find(ARGS, "location", location_idx or host_idx or server_idx)
        server_options = server_options or common.merge(ARGS, common.args(ARGV, options, server_idx, host_idx or next_server_idx))
        host_options = host_options or common.merge(server_options, common.args(ARGV, options, host_idx, location_idx or next_host_idx or next_server_idx))
        location_options = common.merge(host_options, common.args(ARGV, options, host_idx, location_idx or next_host_idx or next_server_idx))
        server = server or Server.new(server_options)
        host = host or Host.new(server, host_options.host, host_options)
        table.insert(host.locations, Location.new(host, host_options.location, host_options))
        location_idx = next_location_idx
      until location_idx and location_idx < (host_idx or server_idx)
      host_idx = next_host_idx
      table.insert(server.hosts, host)
    until host_idx and host_idx < server_idx
    server_idx = next_server_idx
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

  local clients = {}
  local last_active_check = os.time()
  
  while true do
    local socket = ss:poll(10)
    local time = os.time()

    if time - last_active_check > 10 then
      local connections = {}
      for i,v in ipairs(clients) do 
        local timeout = v.location.options.timeout or 60
        if time - v.activity > timeout  then
          v:close()
        elseif not v.closed then
          table.insert(connections, v)
        end
      end
      last_active_check = time
      clients = connections
    end

    if socket then
      local server, client = socket.server
      if server then client = ss:add(socket:accept()) client.message = "" else client = socket end
      client.activity = time

      if not client.ongoing then
        client.message = client.message .. client.message:recv(HEADER_CHUNK_SIZE)
        if server.options.verbose then io.stdout:write(client.message) end
        local version, method, path, headers, body = Request.parse(client.message)
        if version then
          local host = headers["host"]
          for i, h in ipairs(server.hosts) do
            if h.host:find(host) then
              for j, l in ipairs(h.locatoions) do
                local s,e = l.path:find("^" .. path)
                if s then
                  path = path:sub(e + 1)
                  client.ongoing = { location = l, host = host, method = method, path = path, headers = headers }
                  l:init(client, method, path, headers)
                  if body then l:cont(client, method, path, headers, body) end
                  break
                end
              end
            end
          end
        end
      else
        local ongoing = client.ongoing
        local location = ongoing.location
        if location:cont(client, ongoing.method, ongoing.path, ongoing.headers) then
          if not location.keep_alive then client:close() end
          client.activity = os.time()
        end
      end
    end
  end
end, function(err)
  io.stderr:write(err:gsub("^src/main.lua:%d*:%s*", "") .. "\n")
  if LIVE then io.stderr:write(debug.traceback() .. "\n") end
end)

setmetatable(_G, { __index = function(t, k) if not rawget(t, k) then error("cannot get undefined global variable: " .. k, 2) end end, __newindex = function(t, k) error("cannot set global variable: " .. k, 2) end  })

local LOCAL_IO_CHUNK_SIZE = 16*4096
local FORWARD_CHUNK_SIZE = 4096
local HEADER_CHUNK_SIZE = 4096
local MAX_HEADER_SIZE = 4096
local CAN_READ, CAN_WRITE = 1, 2

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
        if not value or value == "" then
          if i >= #arguments then error("option " .. option .. " requires a " .. flag_type) end
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
function common.find(arguments, argument, start_index, end_index)
  for i = start_index or 1, end_index or #arguments do
    if arguments[i]:find("^%-%-" .. argument) then return i end
  end
  return nil
end
function common.merge(...) local t = {} for i,a in ipairs({ ... }) do for k,v in pairs(a) do t[k] = v end end return t end
function common.map(l, f) local t = {} for i,v in ipairs(l) do table.insert(l, f(v)) end return t end

local function log(m)
  io.stdout:write(os.date("[%Y-%m-%dT%H:%M:%S] "))
  io.stdout:write(m)
  io.stdout:write("\n")
end

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

function Request.parse(socket)
  local headers = {}

  local start_of_header, end_of_header
  local idx = 1
  local ibuf = socket.ibuf
  for idx = 1, #ibuf do
    start_of_header, end_of_header = ibuf[idx]:find("\r\n\r\n", 1, true)
    if start_of_header then break end
  end
  if idx == #ibuf and not start_of_header then return end
  local message = table.concat(ibuf, 1, idx)
  local chunks = { }
  for idx = idx + 1, #ibuf do
    table.insert(chunks, ibuf[idx])
  end
  socket.ibuf = chunks
  
  local primary_line = message:find("\r\n")
  local method_end = message:find(" ")
  local path_end = message:find(" ", method_end + 1)
  local method = message:sub(1, method_end - 1)
  local path = message:sub(method_end + 1, path_end - 1)
  local version = message:sub(path_end + 1, primary_line - 1)
  local offset = primary_line + 1
  while offset < start_of_header do
    local s,e = message:find(":%s*", offset)
    local key = message:sub(offset + 1, s - 1):lower()
    offset  = message:find("\r\n", e + 1) + 1
    headers[key] = message:sub(e + 1, offset - 1)
  end
  return version, method, path, headers, message:sub(end_of_header+1)
end

function Request.write(socket, method, path, headers)
  local chunk = method .. " " .. path .. " HTTP/1.1\r\n"
  for k,v in pairs(headers or {}) do chunk = chunk .. (k .. ": " .. v .. "\r\n") end
  chunk = chunk .. "\r\n"
  table.insert(socket.obuf, chunk)
end

function Response.write(socket, code, headers)
  local chunk = "HTTP/1.1 " .. code .. " " .. codes[code] .. "\r\n"
  for k,v in pairs(headers or { ["Content-Length"] = 0 }) do chunk = chunk .. (k .. ": " .. v .. "\r\n") end
  chunk = chunk .."\r\n"
  socket.request.responded = true
  table.insert(socket.obuf, chunk)
end


local Server, Host, Location = {}, {}, {}
function Server.__index(self, k) return rawget(Server, k) end
function Host.__index(self, k) return rawget(Host, k) end
function Location.__index(self, k) return rawget(Location, k) end
function Server.new(options) return setmetatable({ hosts = {}, options = options }, Server) end
function Host.new(server, host, options) return setmetatable({ server = server, locations = {}, host = host, options = options }, Host) end
function Location.new(host, path, options) 
  local self = setmetatable({ host = host, path = path, options = options }, Location) 
  if not self.options.headers then self.options.headers = {} end
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


function Socket:flush()
  if #self.obuf > 0 then
    local sent = self:send(self.obuf[1], self.ooff)
    if sent < #self.obuf[1] - self.ooff then
      self.ooff = sent + self.ooff
    else
      if #self.obuf > 1 then
        local buffer = table.concat(self.obuf, '', 2)
        sent = self:send(buffer, 0)
        self.obuf = sent == #buffer and {} or { buffer }
        self.ooff = #buffer - sent
      else
        self.obuf, self.ooff = {}, 0
      end
    end
  end
  return #self.obuf == 0
end

local mime_types = {
  aac = "audio/aac", abw = "application/x-abiword", arc = "application/x-freearc", avif = "image/avif", avi = "application/vnd.amazon.ebook", bin = "application/octet-stream", bmp = "image/bmp", bz = "application/x-bzip", bz2 = "application/x-bzip2", cda = "application/x-cdf", 
  csh = "application/x-csh", css = "text/css", csv = "text/csv", doc = "application/msword", docx = "application/vnd.openxmlformats-officedocument.wordprocessingml.document", eot = "application/vnd.ms-fontobject", epub  = "application/epub+zip", gz = "application/gzip", gif = "image/gif",
  htm = "text/html", html = "text/html", ico = "image/vnd.microsoft.icon", ics = "text/calendar", jar = "application/java-archive", jpeg = "image/jpeg", jpg = "image/jpeg", js = "text/javascript", json = "application/json", jsonld = "application/ld+json", mid = "audio/midi",
  mjs = "text/javascript", mp3 = "audio/mpeg", mp4 = "video/mp4", mpeg = "video/mpeg", mpkg = "application/vnd.apple.installer+xml", odp = "application/vnd.oasis.opendocument.presentation", ods = "application/vnd.oasis.opendocument.spreadsheet", odt = "application/vnd.oasis.opendocument.text",
  oga = "audio/ogg", ogv = "video/ogg", ogx = "application/ogg", opus = "audio/opus", otf = "font/otf", png = "image/png", pdf = "application/pdf", php = "application/x-httpd-php", ppt = "application/vnd.ms-powerpoint", pptx = "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  rar = "application/vnd.rar", rtf = "application/rtf", sh = "application/x-sh", svg = "image/svg+xml", tar = "application/x-tar", tif = ".tiff	image/tiff", ts = "video/mp2t", ttf = "font/ttf", txt = "text/plain", vsd = "application/vnd.visio", wav = "audio/wav", weba = "audio/webm", webm = "video/webm",
  webp = "image/webp", woff = "font/woff", woff2 = "font/woff2", xhtml = "application/xhtml+xml", xls = "application/vnd.ms-excel", xlsx = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", xml = "application/xml", xul = "application/vnd.mozilla.xul+xml", zip = "application/zip",
  ["3gp"] = "video/3gpp", ["3g2"] = "video/3gpp2", ["7z"] = "application/x-7z-compressed"
}

local function get_mime_type(path)
  local _, _, extension = path:find("%.(%w+)$")
  return (extension and mime_types[extension]) or "application/octet-stream"
end

function Request.init(location, socket, method, path, headers) -- Originally called when we've received all of the header.
  local response_headers = common.merge(location.options.headers)
  if location.options.date then response_headers["Date"] = os.date("%a, %d %b %Y %H:%M:%S %Z") end
  if location.options.static then
    if method ~= "GET" then error({ 405 }) end
    local anchor = type(location.options.static) == "string" and location.options.static or "."
    local stat = system.stat(anchor)
    local target = stat.type == "dir" and (anchor .. PATHSEP .. truncated)  or anchor
    local fh = io.open(target, "rb")
    if not fh then error({ 404 }) end
    socket.static = { stat = stat, fh = fh }
    response_headers["Content-Length"] = stat.size
    response_headers["Content-Type"] = get_mime_type(target)
    Response.write(socket, 200, response_headers)
  elseif location.options.forward then
    local _, _, protocol, host, port = options.forward:find("^(%w+)://([^:]+):?(%d+)$")
    socket.forward = { client = Socket.connect(protocol, host, port), length = headers["Content-Length"] } -- this is blocking for now, may want to change this in future.
    Request.write(socket.forward.client, code, headers)
  elseif location.options.callback then
    location.options.callback(socket, method, path, headers)
  else
    local code = location.options.code or (location.options.body and 200 or 204)
    response_headers["Content-Length"] = location.options.body and #location.options.body or 0
    Response.write(socket, code, response_headers)
    table.insert(socket.obuf, location.options.body)
  end
  return { location = location, method = method, path = path, headers = headers }
end

function Request.on_read(socket) -- Called when we have an incoming chunk for the same request.
  if socket.callback then
    return socket.callback(socket)
  end
  if socket.forward then
    if socket.ioff then
      local chunk = socket.ibuf[1]:sub(socket.ioff)
      table.insert(socket.forward.obuf, chunk)
    end
    for i = 2, #socket.ibuf do
      table.insert(socket.forward.obuf, socket.ibuf[i])
    end
    socket.ibuf = {}
    socket.forward:flush()
    return false
  end
  socket.ibuf, socket.ioff = {}, 0
  return true
end

function Request.on_write(socket) -- Called when we can write outgoing.
  if socket.static then
    local chunk = socket.static.fh:read(LOCAL_IO_CHUNK_SIZE)
    if not chunk then socket.static = nil return true end
    table.insert(socket.obuf, chunk)
    return false
  end
  if socket.forward then
    for i, buf in ipairs(socket.forward.ibuf) do table.insert(socket.obuf, buf) end
    return true
  end
  return true
end


function Request.on_done(socket) -- Called when we've received all the chunks we're going to receive from the client for this request.
  socket:flush()
  socket.request.complete = true
end


function Response.done(socket)
  if socket.close_after_write then socket:close() end
  socket.request = nil
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
    host = "string", gnu = "flag", get = "flag", post = "flag", put = "flag", delete = "flag",
    server = "string", location = "string", host = "string", date = "flag"
  }
  local ARGS = common.args(ARGV, options, 1, server_idx - 1)
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
0                      the path specified is a directory. If it's a file
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
  --date              Adds thes 'Date' header to the response.
  --[get|post|...]    Limits interactions to only these methods.
  
]]
    )
    return 0
  end
  if not server_idx then error("can't find --server specifier") end
  while server_idx do
    local server, host_idx, next_host_idx, server_options
    local next_server_idx = common.find(ARGV, "server", server_idx + 1)
    repeat
      local host, next_location_idx, host_options
      local next_host_idx = common.find(ARGV, "host", (host_idx or server_idx) + 1, next_server_idx)
      local location_idx = common.find(ARGV, "location", (host_idx or server_idx) + 1, (next_host_idx or next_server_idx))
      local host_options = common.merge(server_options, common.args(ARGV, options, host_idx or server_idx, (location_idx or next_host_idx or next_server_idx or (#ARGV+1)) - 1 ))
      repeat
        next_location_idx = common.find(ARGV, "location", (location_idx or host_idx or server_idx) + 1, next_host_idx or next_server_idx)
        server_options = server_options or common.merge(ARGS, common.args(ARGV, options, server_idx, host_idx or next_server_idx))
        local location_options = common.merge(host_options, common.args(ARGV, options, location_idx or host_idx or server_idx, (next_location_idx or next_host_idx or next_server_idx or (#ARGV+1)) - 1))
        server = server or Server.new(server_options)
        host = host or Host.new(server, host_options.host or ".", host_options)
        table.insert(host.locations, Location.new(host, location_options.location or "/", location_options))
        location_idx = next_location_idx
      until not location_idx
      host_idx = next_host_idx
      table.insert(server.hosts, host)
    until not host_idx or host_idx > server_idx
    server_idx = next_server_idx
    table.insert(servers, server)
  end
  local ss = SocketSet.new()
  local sockets, address, port = {}
  for i, server in ipairs(servers) do
    port = select(3, server.options.server:find("^(%d+)$"))
    if not port then address, port = select(3, server.options.server:find("([^:]+):?(%d+)")) else address = "0.0.0.0" end
    if not address then error("can't parse server address " .. server.options.server) end
    local ssl = nil
    if server.options.ssl_key or server.options.ssl_cert then
      if not server.options.ssl_key then error("must supply an ssl_key alongside an ssl_cert") end
      if not server.options.ssl_cert then error("must supply an ssl_cert alongside an ssl_key") end
      ssl = { server.options.ssl_cert, server.options.ssl_key }
    elseif server.options.ssl_callback then
      ssl = parse_function_or_path(sever.options.ssl_callback)
    end
    local socket = ss:add(Socket.listen(address, port, { ssl = ssl }))
    server.socket, socket.server = socket, server
  end

  local clients = {}
  local last_active_check = os.time()

  log("Spinning up server...")
  while true do
    local socket, event = ss:poll(10)
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
      if not socket.ibuf then 
        client = ss:add(socket:accept()) 
        client.ibuf, client.obuf, client.ioff, client.ooff, client.server = {}, {}, 0, 0, server
      else 
        client = socket 
      end
      client.activity = time
      local status, err = pcall(function()
        if event & CAN_READ then
          local chunk = client:recv(HEADER_CHUNK_SIZE)
          if #chunk > 0 then
            table.insert(client.ibuf, chunk)
            if not client.request then -- If we don't have an ongoing request.
              local version, method, path, headers, body, index, offset = Request.parse(client)
              if version then
                if index then 
                  client.ioff = offset
                  local buf = { } 
                  table.setn(buf, #client.ibuf - index)
                  for i = index, #client.ibuf do buf[i - index + 1] = client.ibuf[i] end
                end
                client.request = { responded = false }
                local host = headers["host"]
                for i, h in ipairs(server.hosts) do
                  if host:find(h.host) then
                    client.host = h
                    for j, l in ipairs(h.locations) do
                      if path:find("^" .. l.path) then
                        client.request = Request.init(l, client, method, path, headers)
                        log("Request " .. method .. " " .. path)
                        if #client.ibuf then Request.on_read(client) end
                        if method == "GET" then Request.on_done(client) end
                        event = event | CAN_WRITE
                        break
                      end
                    end
                  end
                end
                if client.request and not client.request.location then
                  log("Request " .. method .. " " .. path)
                  error({ 404 })
                end
              else
                local length = 0 for i = 1, #client.ibuf do length = length + #client.ibuf[i] end
                if length >= MAX_HEADER_SIZE then error({ 431 }) end
              end
            else
              if Request.on_read(client) then
                if client.location and not client.location.settings.keep_alive then client.close_after_write = true end
              end
            end
          end
        end
        if client.request and client.request.location and (event & CAN_WRITE) then
          local finished, fully_flushed
          repeat 
            finished = Request.on_write(client)
            fully_flushed = client:flush()
          until not fully_flushed or finished
          if fully_flushed and finished then
            Response.done(client)
          end
        end
      end)
      if not status then
        if client and type(err) == "table" then
          if client.request and not client.request.responded then
            Response.write(client, table.unpack(err))
            Response.done(client)
            client:flush()
          else
            client:close()
          end
        elseif client then
          log(err)
          client:close()
        else
          error(err)
        end
      end
    end
  end
end, function(err)
  io.stderr:write(err:gsub("^src/main.lua:%d*:%s*", "") .. "\n")
  if LIVE then io.stderr:write(debug.traceback() .. "\n") end
end)

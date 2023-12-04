function read(path) return io.open(path, "rb"):read("*all") end
function filter(l ,f) local t = {} for i,v in ipairs(l) do if f(v) then table.insert(t, v) end end return t end
setmetatable(_G, { __index = function(t, k) if not rawget(t, k) then error("cannot get undefined global variable: " .. k, 2) end end, __newindex = function(t, k) error("cannot set global variable: " .. k, 2) end  })

local LOCAL_IO_CHUNK_SIZE = 16*4096
local FORWARD_CHUNK_SIZE = 4096
local INCREMENTAL_CHUNK_SIZE = 4096
local MAX_HEADER_SIZE = 8*1024
local MAX_LINE_SIZE = 4096
local DEFAULT_TIMEOUT = 60
local POLL_MAX_TIME = 10
local INACTIVITY_CHECK_TIME = 10


local function log(m, prefix)
  io.stdout:write(os.date("[%Y-%m-%dT%H:%M:%S]"))
  if prefix then io.stdout:write(prefix) end
  io.stdout:write(" ")
  io.stdout:write(tostring(m))
  io.stdout:write("\n")
end

local CoSocket = {}
CoSocket.__index = CoSocket
function CoSocket:flushread(noflush)
  local ibuf = self.ibuf
  if not noflush then
    if self.ibuf ~= '' then self.activity = os.time() end
    self.ibuf = ''
  end
  return ibuf
end
function CoSocket:log(m)
  if self.ip then
    log(m, "[" .. self.id .. "][" .. self.ip .. "]")
  else
    log(m, "[" .. self.id .. "]")
  end
end
-- Read function, reads exactly N amount of bytes, or a line or all.
function CoSocket:read(toread, nonblocking, throw, noflush)
  if not self.ibuf then self.ibuf = '' end
  while true do
    if type(toread) == 'number' then
      if #self.ibuf >= toread then
        local ret = self.ibuf:sub(1, toread)
        self.ibuf = self.ibuf:sub(toread)
        return ret
      end
      local ret, err = self.socket:read(toread - #self.ibuf)
      if ret == nil then if throw then error(err) end return self:flushread(noflush) end
      if ret == '' then if nonblocking then return self:flushread(noflush) else coroutine.yield(self) end
      else self.ibuf = self.ibuf .. ret end
      return self:flushread(noflush)
    else
      if toread == "*line" then
        local s,e = self.ibuf:find("\r\n")
        if s then
          local res = self.ibuf:sub(1, s - 1)
          self.ibuf = self.ibuf:sub(e + 1)
          self.activity = os.time()
          return res
        elseif #self.ibuf > MAX_LINE_SIZE then
          return self:flushread(noflush)
        end
        local ret = self.socket:read(INCREMENTAL_CHUNK_SIZE)
        if ret == nil then if throw then error(err) end return self:flushread(noflush) end
        if ret == '' then if nonblocking then return self:flushread(noflush) else coroutine.yield(self) end end
        self.ibuf = self.ibuf .. ret
      elseif toread == "*all" or toread == "*chunk" then
        local ret = self.socket:read(self, 100*1024)
        if ret == '' then if nonblocking then return self:flushread(noflush) else coroutine.yield(self) end
        elseif ret == nil then if throw then error(err) end return self:flushread(noflush)
        else
          self.ibuf = self.ibuf .. ret
          if toread == "*chunk" then return self:flushread(noflush) end
        end
      end
    end
  end
end
function CoSocket:peek(len) return self:read(len, true, false, true) end

function CoSocket:write(chunk)
  self.activity = os.time()
  return self.socket:write(chunk)
end
function CoSocket:close(...) return self.socket:close() end
function CoSocket.connect(parent, ...)
  local client = setmetatable({ socket = Socket.connect(...), pending = {}, activity = os.time(), client = parent }, CoSocket)
  coroutine.yield(client)
  return client
end
function CoSocket.listen(...) return setmetatable({ socket = Socket.listen(...), pending = {}, activity = os.time() }, CoSocket) end
function CoSocket:accept(...)
  local socket = self.socket:accept()
  if not socket then return nil end
  local client = setmetatable({ socket = socket, pending = {}, activity = os.time(), server = self.server, forwards = {} }, CoSocket)
  client.ip = socket:peer()
  return client
end
function CoSocket:handshake(...)
  while self.server.ssl and not self.socket:handshake(self.server.ssl) do
    coroutine.yield(self)
  end
end

local old_pending_add = Pending.add
function Pending:add(cosocket)
  if not self.mapping then self.mapping = {} end
  self.mapping[cosocket.socket] = cosocket
  old_pending_add(self, cosocket.socket)
  return cosocket
end
local old_pending_poll = Pending.poll
function Pending:poll(...)
  local socket = old_pending_poll(self, ...)
  return self.mapping[socket]
end
local old_pending_remove = Pending.remove
function Pending:remove(cosocket)
  self.mapping[cosocket.socket] = nil
  old_pending_remove(self, cosocket.socket)
end


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
      elseif flag_type == "string" or flag_type == "number" or flag_type == "integer" then
        if not value or value == "" then
          if i >= #arguments then error("option " .. option .. " requires a " .. flag_type) end
          value = arguments[i+1]
          i = i + 1
        end
        if flag_type == "number" or flag_type == "integer" and tonumber(value) == nil then error("option " .. option .. " should be a number") end
        args[option] = flag_type == "number" or flag_type == "integer" and tonumber(value) or value
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
    for k, arg in ipairs(type(argument) == "table" and argument or { argument }) do
      if arguments[i]:find("^%-%-" .. arg) then return i end
    end
  end
  return nil
end

function common.merge(...) local t = {} for i,a in ipairs({ ... }) do for k,v in pairs(a) do t[k] = v end end return t end
function common.map(l, f) local t = {} for i,v in ipairs(l) do table.insert(l, f(v)) end return t end
function common.grep(l, f) local t = {} for i,v in ipairs(l) do if f(v) then table.insert(l, v) end end return t end
function table.append(t1, t2) for i,v in ipairs(t2) do table.insert(t1, v) end end


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
  [507] = "Insufficient Storage", [508] = "Loop Detected", [510] = "Not Extended", [511] = "Network Authentication Required", [512] = "Bad Gateway"
}

function Request.parse(socket, nonblocking)
  if nonblocking and not socket:peek(MAX_HEADER_SIZE):find("\r\n\r\n") then return nil end
  local _, _, method, path, version = socket:read("*line", nonblocking, true):find("^(%w+) (%S+) HTTP/([%d%.]+)$")
  if not method then error("malformed request line") end
  local headers = {}
  while true do
    local line = socket:read("*line", nonblocking)
    if line == '' then break end
    local s,e = line:find("%s*:%s*")
    if not s then error("malformed header") end
    headers[line:sub(1, s-1):lower()] = line:sub(e+1)
  end
  return { version = version, method = method, path = path, headers = headers }
end

function Request.write(method, path, headers)
  local chunk = method .. " " .. path .. " HTTP/1.1\r\n"
  for k,v in pairs(headers or {}) do chunk = chunk .. (k .. ": " .. v .. "\r\n") end
  return chunk .. "\r\n"
end


function Response.parse(socket, nonblocking)
  if nonblocking and not socket:peek(MAX_HEADER_SIZE):find("\r\n\r\n") then return nil end
  local _, _, version, code, status = socket:read("*line"):find("^HTTP/([%d%.]+) (%d+) (.*)$")
  if not version then error("malformed request line") end
  local headers = {}
  while true do
    local line = socket:read("*line")
    if line == '' then break end
    local s,e = line:find("%s*:%s*")
    if not s then error("malformed header") end
    headers[line:sub(1, s-1):lower()] = line:sub(e+1)
  end
  return { version = version, code = code, status = status, headers = headers }
end

function Response.write(code, headers)
  local chunk = "HTTP/1.1 " .. code .. " " .. (codes[code] or "Unknown") .. "\r\n"
  for k,v in pairs(headers or { ["Content-Length"] = 0 }) do chunk = chunk .. (k .. ": " .. v .. "\r\n") end
  return chunk .."\r\n"
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


local mime_types = {
  aac = "audio/aac", abw = "application/x-abiword", arc = "application/x-freearc", avif = "image/avif", avi = "application/vnd.amazon.ebook", bmp = "image/bmp", bz = "application/x-bzip", bz2 = "application/x-bzip2", cda = "application/x-cdf",
  csh = "application/x-csh", css = "text/css", csv = "text/csv", doc = "application/msword", docx = "application/vnd.openxmlformats-officedocument.wordprocessingml.document", eot = "application/vnd.ms-fontobject", epub  = "application/epub+zip", gz = "application/gzip", gif = "image/gif",
  htm = "text/html", html = "text/html", ico = "image/vnd.microsoft.icon", ics = "text/calendar", jar = "application/java-archive", jpeg = "image/jpeg", jpg = "image/jpeg", js = "text/javascript", json = "application/json", jsonld = "application/ld+json", mid = "audio/midi",
  mjs = "text/javascript", mp3 = "audio/mpeg", mp4 = "video/mp4", mpeg = "video/mpeg", mpkg = "application/vnd.apple.installer+xml", odp = "application/vnd.oasis.opendocument.presentation", ods = "application/vnd.oasis.opendocument.spreadsheet", odt = "application/vnd.oasis.opendocument.text",
  oga = "audio/ogg", ogv = "video/ogg", ogx = "application/ogg", opus = "audio/opus", otf = "font/otf", png = "image/png", pdf = "application/pdf", php = "application/x-httpd-php", ppt = "application/vnd.ms-powerpoint", pptx = "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  rar = "application/vnd.rar", rtf = "application/rtf", sh = "application/x-sh", svg = "image/svg+xml", tar = "application/x-tar", tif = "image/tiff", tiff = "image/tiff", ts = "video/mp2t", ttf = "font/ttf", txt = "text/plain", vsd = "application/vnd.visio", wav = "audio/wav", weba = "audio/webm", webm = "video/webm",
  webp = "image/webp", woff = "font/woff", woff2 = "font/woff2", xhtml = "application/xhtml+xml", xls = "application/vnd.ms-excel", xlsx = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", xml = "application/xml", xul = "application/vnd.mozilla.xul+xml", zip = "application/zip",
  ["3gp"] = "video/3gpp", ["3g2"] = "video/3gpp2", ["7z"] = "application/x-7z-compressed", md = "text/markdown"
}

local function get_mime_type(path)
  local _, _, extension = path:find("%.(%w+)$")
  return (extension and mime_types[extension]) or "application/octet-stream"
end

function Host:handle(socket, request)
  for _, location in ipairs(self.locations) do
    if request.path:find("^" .. location.path) == 1 then
      location:handle(socket, request)
      return
    end
  end
  socket:log("> " .. request.method .. " " .. request.path)
end

function Location:handle(socket, request) -- Originally called when we've received all of the header.
  socket.processing = false
  local response = { headers = common.merge(self.options.headers), code = 500 }
  socket:log("> " .. request.method .. " " .. request.path)
  if self.options.date then response.headers["Date"] = os.date("%a, %d %b %Y %H:%M:%S %Z") end
  if self.options.static then
    if request.method ~= "GET" then error({ 405 }) end
    local anchor = type(self.options.static) == "string" and self.options.static or "."
    local stat = system.stat(anchor)
    local s,e = request.path:find("^" .. self.path)
    local target = stat.type == "dir" and (anchor .. PATHSEP .. request.path:sub(e + 1)) or anchor
    stat = system.stat(target)
    if not stat then error({ 404 }) end
    if stat.type == "dir" then target = target .. PATHSEP .. (self.options.index or "index.html") end
    stat = system.stat(target)
    local fh = io.open(target, "rb")
    if not fh then error({ 404 }) end
    response.headers["Content-Length"] = stat.size
    response.headers["Content-Type"] = get_mime_type(target)
    response.code = 200
    socket:write(Response.write(response.code, response.headers))
    while true do
      local chunk = fh:read(LOCAL_IO_CHUNK_SIZE)
      if not chunk then break end
      socket:write(chunk)
      coroutine.yield()
    end
  elseif self.options.forward then -- in this case, obuf on the forward client is headed out to upstream, ibuf, returning from upstream.
    local _, _, protocol, host, port = self.options.forward:find("^(%w+)://([^:]+):?(%d*)$")
    if not protocol then error("can't parse forwarding string " .. self.options.forward) end
    local client
    if not socket.forwards[self.options.forward] then
      local status, new_client = pcall(CoSocket.connect, socket, protocol, host, port)  -- this is blocking for now, may want to change this in future.
      if not status then
        socket:log(new_client)
        error({ 512 })
      end
      socket.forwards[self.options.forward] = new_client
      client = new_client
    end
    client:write(Request.write(request.method, request.path, request.headers))
    local outgoing_response
    local content_length_left = nil
    while true do
      local connected_incoming = true
      local connected_outgoing = true
      local incoming_chunk = socket:read(FORWARD_CHUNK_SIZE, true)
      if incoming_chunk and #incoming_chunk > 0 then client:write(incoming_chunk) end
      if not outgoing_response then
        outgoing_response = Response.parse(client, true)
        if outgoing_response then
          response.code = self.options.code or outgoing_response.code
          response.headers = common.merge(outgoing_response.headers, response.headers)
          socket:write(Response.write(response.code, response.headers))
          content_length_left = outgoing_response.headers.content_length
        end
      else
        local outgoing_chunk = client:read(content_length_left or FORWARD_CHUNK_SIZE, true)
        if outgoing_chunk and #outgoing_chunk > 0 then
          socket:write(outgoing_chunk)
          if content_length_left then
            content_length_left = content_length_left - #outgoing_chunk
            if content_length_left == 0 then break end
          end
        end
      end
      if not connected_incoming or not connected_outgoing then
        socket:close()
        client:close()
        break
      end
      coroutine.yield(socket, client)
    end
  elseif self.options.callback then
    response = self.options.callback(socket, request)
  else
    response.code = self.options.code or (self.options.body and 200 or 204)
    response.headers["Content-Length"] = self.options.body and #self.options.body or 0
    socket:write(Response.write(response.code, response.headers))
    if self.options.body then socket:write(self.options.body) end
  end
  if request.headers.connection == "close" and not response.headers["Connection"] then response.headers["Connection"] = "close" end
  if response.headers["Connection"] == "close" then socket:close() end
  if response.headers["Content-Length"] then
    socket:log("< " .. response.code .. " " .. response.headers["Content-Length"])
  else
    socket:log("< " .. response.code)
  end
end


local function parse_function_or_path(path_or_function)
  local chunk, err
  if not path_or_function:find(".lua$") then
    chunk, err = load(path_or_function)
  else
    chunk, err = loadfile(path_or_function)
  end
  if not chunk then error(err) end
  return chunk
end

local function incoming_request(socket)
  xpcall(function()
    socket:handshake()
    socket.processing = true
    local request = Request.parse(socket)
    local request_host = request.headers.host:gsub(":*$", "")
    for i, host in ipairs(socket.server.hosts) do
      if request_host:find("^" .. host.host .. "$") == 1 then
        return host:handle(socket, request)
      end
    end
    socket:log("> " .. request.method .. " " .. request.path)
    error({ 404 })
  end, function(err)
    if type(err) == 'table' then
      local body = codes[err[1]] or "Internal Server Error"
      local code = codes[err[1]] and err[1] or 500
      socket:write(Response.write(code, { ["Content-Length"] = #body, ["Content-Type"] = "text/plain" }))
      socket:write(body)
      socket:log("< " .. code .. " " .. #body)
    else
      if socket.processing then
        local body = "Internal Server Error"
        socket:write(Response.write(code, { ["Content-Length"] = #body, ["Content-Type"] = "text/plain" }))
        socket:write(body)
        socket:log("< " .. code .. " " .. #body)
      end
      if socket.server.options.verbose then
        io.stderr:write(err .. "\n")
        io.stderr:write(debug.traceback(nil, 3) .. "\n")
      end
    end
    socket:close()
  end)
  if socket.server.options.once then socket.server.done = true end
  socket.processing = false
end

xpcall(function()
  local server_idx = common.find(ARGV, { "server", "sserver" })
  local options = {
    ssl_cert = "string", ssl_key = "string", ssl = "string", location = "string",
    static = "string", forward = "string", timeout = "integer", code = "integer",
    header = "list", body = "string", callback = "string", error = "string",
    stdout = "string", stderr = "string", compress = "string", inherit = "string",
    redirect = "string", verbose = "flag", version = "flag", help = "flag", plugin = "string",
    host = "string", gnu = "flag", get = "flag", post = "flag", put = "flag", delete = "flag",
    server = "string", location = "string", host = "string", date = "flag", ["lets-encrypt"] = "string",
    sserver = "flag", hostdir = "string", once = "flag"
  }
  if ARGV[2] == "test" then
    rawset(_G, 'arg', { select(4, table.unpack(ARGV)) })
    dofile(ARGV[3])
  end
  local ARGS = common.args(ARGV, options, 2, server_idx and (server_idx - 1))
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
switches, though you can have one if it makes you happy. Releases are linked
with musl, and are static, so should run pretty much anywhere.

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
                      if specified, listens off STDIN. If no `.` is present
                      assumes 0.0.0.0. If not supplied, listens on
                      0.0.0.0:8080.
  --sserver           As above, but listens exactly on 80 and 443. Any
                      `ssl_` options won't affect the 80 server.

Server Flags

  If no server has been specified, affects all servers, otherwise
  affects only the most recently specified server.

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
  only the most recently specified host within the most recent server.
  If no server is specified, is global.

  --host=hostname     Specifies the hostname to listen for.
  --hostdir=./*       Specifies a directory. Acts as new working directory for
                      subsequent options. If a wildcard, will repeat all
                      following options for each directory, with the #HOST
                      variable set.

  --ssl_cert=path     Specifies the certificate path.
  --ssl_key=path      Specifies the private key.
  --ssl=...           Specifies a literal lua function body to return
                      [certificate, private_key, ca_chain], taking (hostname).
                      ca_chain is optional.
                      If it specifies a path, will load the lua file/shared
                      library at that location, and call it.
  --lets-encrypt=path Specifies your let's encrypt private key. If specified
                      with --ssl_cert and and --ssl_key, can be used to
                      request a let's encrypt key. Only applies i

Location Flags

  If no location has been specified, affects all subsequent locations for
  this server. If no server has been specified affects all locations. Any
  string can specify an incoming all caps header value with the name
  of the header preceded by a $ ($PATH). Query parameters can be specified
  with a % (%q). These can be escaped with backslash. Location can be
  accessed with a #, (#LOCATION).

  --static=path       Statically serves content located at the path, if
                      the path specified is a directory. If it's a file
                      serves that file.
  --index=index.*     Sets the index file for statically served content.
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
  --error=...         Specifies a location where errors are to be routed.
                      If specifies as a comma separated list of numbers,
                      followed by a colon, then the location, only routes
                      those specifies errors. If the location is a path,
                      will use that path and serve the file there.
  --std[out|err]=...  Logs to the specified file. Specify /dev/null
                      to discard.
  --compress=deflate  Compresses all non-media responses with DEFLATE encoding.
                      Adds appropriate header.
  --inherit=location  Specifies that we should inherit all settings from
                      the specified location and override.
  --redirect=url      A quick way of specying a 302.
  --verbose           Dumps requests and responses to STDOUT.
  --gnu               Adds 'X-Clacks-Overhead: GNU Terry Pratchett' header.
  --date              Adds thes 'Date' header to the response.
  --[get|post|...]    Limits interactions to only these methods.
  --once              Runs for one request.

Examples


]]
    )
    return 0
  end
  local all_servers = {}
  local connection_id = 0
  if not server_idx then server_idx = 2 end
  while server_idx do
    local servers, host_idx, next_host_idx, server_options
    local next_server_idx = common.find(ARGV, { "server", "sserver" }, server_idx + 1)
    repeat
      local hosts, next_location_idx, host_options
      local next_host_idx = common.find(ARGV, { "host", "hostdir" }, (host_idx or server_idx) + 1, next_server_idx)
      local location_idx = common.find(ARGV, "location", (host_idx or server_idx) + 1, (next_host_idx or next_server_idx))
      local host_options = common.merge(server_options, common.args(ARGV, options, host_idx or server_idx, (location_idx or next_host_idx or next_server_idx or (#ARGV+1)) - 1 ))
      repeat
        next_location_idx = common.find(ARGV, "location", (location_idx or host_idx or server_idx) + 1, next_host_idx or next_server_idx)
        server_options = server_options or common.merge(ARGS, common.args(ARGV, options, server_idx, host_idx or next_server_idx))
        local location_options = common.merge(host_options, common.args(ARGV, options, location_idx or host_idx or server_idx, (next_location_idx or next_host_idx or next_server_idx or (#ARGV+1)) - 1))
        if not server_options.server then server_options.server = "0.0.0.0:8080" end
        servers = servers or { Server.new(server_options) }
        for _, server in ipairs(servers) do
          hosts = hosts or { Host.new(server, host_options.host or ".*", host_options) }
          for _, host in ipairs(hosts) do
            table.insert(host.locations, Location.new(host, location_options.location or "/", location_options))
          end
        end
        location_idx = next_location_idx
      until not location_idx
      host_idx = next_host_idx
      for i,server in ipairs(servers) do
        table.append(server.hosts, hosts)
      end
    until not host_idx or host_idx > server_idx
    server_idx = next_server_idx
    table.append(all_servers, servers)
  end
  local pending = Pending.new()
  local sockets, address, port = {}
  for i, server in ipairs(all_servers) do
    for _, host in ipairs(server.hosts) do
      table.sort(host.locations, function(a,b) return #b.path < #a.path end)
    end
    table.sort(server.hosts, function(a,b) return #b.host < #a.host end)
    port = select(3, server.options.server:find("^(%d+)$"))
    if not port then address, port = select(3, server.options.server:find("([^:]+):?(%d+)")) else address = "0.0.0.0" end
    if not address then error("can't parse server address " .. server.options.server) end
    local ssl = nil
    if server.options.ssl_key or server.options.ssl_cert then
      if not server.options.ssl_key then error("must supply an ssl_key alongside an ssl_cert") end
      if not server.options.ssl_cert then error("must supply an ssl_cert alongside an ssl_key") end
      ssl = function(...) return read(server.options.ssl_cert), read(server.options.ssl_key) end
    elseif server.options.ssl then
      ssl = parse_function_or_path(server.options.ssl)
    end
    server.ssl = ssl
    server.socket = pending:add(CoSocket.listen(address, port, ssl))
    server.socket.server = server
  end

  local clients = {}
  local last_active_check = os.time()

  log("Spinning up server...")
  local active_connections = {} -- Connections that are actively doing something, and not waiting on anything.
  while #all_servers > 0 do
    local socket
    if #active_connections > 0 then
      socket = pending:poll(0)
      if not socket then
        socket = active_connections[1]
        if socket then table.remove(active_connections, 1) end
      end
    else
      socket = pending:poll(POLL_MAX_TIME)
    end
    local time = os.time()
    if time - last_active_check > INACTIVITY_CHECK_TIME and #clients > 0 then
      local connections = {}
      for i,v in ipairs(clients) do
        local timeout = v.server.options.timeout or DEFAULT_TIMEOUT
        if time - v.activity > timeout then
          if v.server.options.verbose then v:log(string.format("Connection closed due to timeout.", v.id)) end
          v:close()
        elseif not v.closed then
          table.insert(connections, v)
        end
      end
      last_active_check = time
      clients = connections
      if ARGS["verbose"] then log(string.format("Active connection purge; %d active connections remain.", #clients)) end
    end

    if socket then
      if not socket.client then
        local client = socket:accept()
        connection_id = connection_id + 1
        client.id = connection_id
        table.insert(clients, client)
        client.client = client
        socket = client
      else
        socket = socket.client
      end
      for _,v in ipairs(socket.client.pending) do pending:remove(v) end
      socket.client.pending = {}
      socket.coroutine = socket.coroutine or coroutine.create(incoming_request)
      local waiting = { select(2, coroutine.resume(socket.coroutine, socket)) }
      if coroutine.status(socket.coroutine) == 'dead' then
        socket.coroutine = nil
      end
      if #waiting > 0 then
        socket.client.pending = waiting
        for i = 1, #waiting do pending:add(waiting[i]) end
      elseif socket.coroutine then
        table.insert(active_connections, socket)
      end
      if socket.server.done then
        pending:remove(socket.server.socket)
        all_servers = filter(all_servers, function(s) return s ~= socket.server end)
      end
    end
  end
  log("Done.")
end, function(err)
  io.stderr:write(err:gsub("^src/main.lua:%d*:%s*", "") .. "\n")
  if LIVE then io.stderr:write(debug.traceback(nil, 2) .. "\n") end
end)

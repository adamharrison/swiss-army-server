#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <math.h>
#include <pthread.h>

#include <mbedtls/sha256.h>
#include <mbedtls/x509.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>


#define MAX_EVENTS 10

struct Pending {
  int epollfd;
  struct epoll_event events[MAX_EVENTS];
};

enum ESocketType {
  SOCKET_TYPE_CLOSED   = 0x00,
  SOCKET_TYPE_FILE     = 0x01,
  SOCKET_TYPE_SERVER   = 0x02,
  SOCKET_TYPE_CLIENT   = 0x03,
  SOCKET_TYPE_PIPE     = 0x04,
  SOCKET_TYPE_MASK     = 0x07,
  SOCKET_HAS_SSL       = 0x08,
  SOCKET_HAS_CALLBACK  = 0x10
};

struct Socket {
  int type;
  int fds[2];                       // Bidirectional pipe for SOCKET_TYPE_PIPE, otherwise, signle fd.
  time_t last_activity;             // time
};

struct SSLSocket {
  struct Socket socket;
  char peer[128];
  mbedtls_ssl_config config;
  mbedtls_ssl_context ssl_context;
  mbedtls_net_context net_context;
  int handshook;
  mbedtls_x509_crt certificate; // The SSL certificate for this client.
  mbedtls_pk_context private_key; // The SSL private_key for this client.
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
};

static struct Socket* lua_newsocket(lua_State* L, int type) {
  int size = ((type & SOCKET_HAS_SSL) != 0) ? sizeof(struct SSLSocket) : sizeof(struct Socket);
  struct Socket* socket = lua_newuserdata(L, size);
  memset(socket, 0, size);
  socket->type = type;
  luaL_setmetatable(L, "Socket");
  return socket;
}

static int lua_mbedtls_error(lua_State* L, int code, const char* str, ...) {
  char vsnbuffer[1024];
  char mbed_buffer[128];
  mbedtls_strerror(code, mbed_buffer, sizeof(mbed_buffer));
  va_list va;
  va_start(va, str);
      vsnprintf(vsnbuffer, sizeof(vsnbuffer), str, va);
  va_end(va);
  lua_pushfstring(L, "%s: %s", vsnbuffer, mbed_buffer);
  return code;
}

static int luaL_mbedtls_error(lua_State* L, int code, const char* str, ...) {
  char vsnbuffer[1024];
  char mbed_buffer[128];
  mbedtls_strerror(code, mbed_buffer, sizeof(mbed_buffer));
  va_list va;
  va_start(va, str);
      vsnprintf(vsnbuffer, sizeof(vsnbuffer), str, va);
  va_end(va);
  return luaL_error(L, "%s: %s", vsnbuffer, mbed_buffer);
}

static int f_pending_new(lua_State *L) {
  lua_newtable(L);
  lua_newtable(L);
  lua_newtable(L);
  lua_pushliteral(L, "k");
  lua_setfield(L, -2, "__mode");
  lua_setmetatable(L, -2);
  lua_setfield(L, -2, "sockets");
  struct Pending* s = lua_newuserdata(L, sizeof(struct Pending));
  lua_setfield(L, -2, "set");
  s->epollfd = epoll_create1(0);
  if (s->epollfd == -1)
    return luaL_error(L, "can't create epoll: %s", strerror(errno));
  luaL_setmetatable(L, "Pending");
  return 1;
}


static int f_pending_add(lua_State* L) {
  lua_getfield(L, 1, "set");
  struct Pending* socket_set = lua_touserdata(L, -1);
  struct epoll_event ev;
  ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
  struct Socket* socket = lua_touserdata(L, 2);
  int max_fds = (socket->type & SOCKET_TYPE_MASK) == SOCKET_TYPE_PIPE ? 2 : 1;
  for (int i = 0; i < max_fds; ++i) {
    ev.data.fd = socket->fds[i];
    if (epoll_ctl(socket_set->epollfd, EPOLL_CTL_ADD, ev.data.fd, &ev) == -1)
      return luaL_error(L, "can't add socket %d: %s", ev.data.fd, strerror(errno));
  }
  lua_getfield(L, 1, "sockets");
  for (int i = 0; i < max_fds; ++i) {
    lua_pushinteger(L, socket->fds[i]);
    lua_pushvalue(L, 2);
    lua_rawset(L, -3);
  }
  lua_pop(L, 1);
  return 1;
}


static int f_pending_remove(lua_State* L) {
  lua_getfield(L, 1, "set");
  struct Pending* socket_set = lua_touserdata(L, -1);
  struct epoll_event ev;
  ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
  struct Socket* socket = lua_touserdata(L, 2);
  int max_fds = (socket->type & SOCKET_TYPE_MASK) == SOCKET_TYPE_PIPE ? 2 : 1;
  for (int i = 0; i < max_fds; ++i) {
    ev.data.fd = socket->fds[i];
    if (epoll_ctl(socket_set->epollfd, EPOLL_CTL_DEL, ev.data.fd, &ev) == -1)
      return luaL_error(L, "can't add socket %d: %s", ev.data.fd, strerror(errno));
  }
  lua_getfield(L, 1, "sockets");
  for (int i = 0; i < max_fds; ++i) {
    lua_pushinteger(L, socket->fds[i]);
    lua_pushnil(L);
    lua_rawset(L, -3);
  }
  lua_pop(L, 1);
  return 1;
}


static int f_pending_poll(lua_State* L) {
  double timeout = luaL_checknumber(L, 2);
  lua_getfield(L, 1, "set");
  struct Pending* socket_set = lua_touserdata(L, -1);
  int nfds = epoll_wait(socket_set->epollfd, socket_set->events, MAX_EVENTS, (int)(timeout * 1000.0));
  if (nfds == -1)
    return luaL_error(L, "can't poll: %s", strerror(errno));
  if (nfds == 0)
    return 0;
  lua_pop(L, 1);
  lua_getfield(L, 1, "sockets");
  lua_pushinteger(L, socket_set->events[0].data.fd);
  lua_rawget(L, -2);
  lua_pushinteger(L, ((socket_set->events[0].events & EPOLLIN) ? 1 : 0) | ((socket_set->events[0].events & EPOLLOUT) ? 2 : 0));
  return 2;
}


static int f_pending_close(lua_State* L) {
  lua_getfield(L, 1, "set");
  struct Pending* s = lua_touserdata(L, -1);
  close(s->epollfd);
  return 1;
}

static int f_socket_listen(lua_State* L) {
  int ssl = lua_toboolean(L, 3);
  if (ssl) {
    struct SSLSocket* server = (struct SSLSocket*)lua_newsocket(L, SOCKET_TYPE_SERVER | SOCKET_HAS_SSL);
    mbedtls_ssl_config_init(&server->config);
    mbedtls_ssl_init(&server->ssl_context);
    mbedtls_net_init(&server->net_context);
    char port[64];
    snprintf(port, sizeof(port), "%lld", luaL_checkinteger(L, 2));
    mbedtls_net_bind(&server->net_context, luaL_checkstring(L, 1), port, MBEDTLS_NET_PROTO_TCP);
    server->socket.fds[0] = server->net_context.fd;
    int ret = mbedtls_ssl_config_defaults(&server->config, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret < 0)
      return luaL_mbedtls_error(L, ret, "can't set defaults");
  } else {
    struct Socket* server = lua_newsocket(L, SOCKET_TYPE_SERVER);
    struct sockaddr_in addr = { .sin_family = AF_INET };
    addr.sin_addr.s_addr = inet_addr(luaL_checkstring(L, 1));
    addr.sin_port = htons(luaL_checkinteger(L, 2));
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int flag = 1;
    if (s < 0)
      return luaL_error(L, "can't open socket: %s", strerror(errno));
    if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &flag, sizeof(flag)) || bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0 || listen(s, 1) < 0) {
      close(s);
      return luaL_error(L, "can't listen on socket: %s", strerror(errno));
    }
    server->fds[0] = s;
  }
  return 1;
}

static int f_socket_peer(lua_State* L) {
  struct Socket* self = lua_touserdata(L, 1);
  if (!(self->type & SOCKET_TYPE_CLIENT))
    return 0;
  if (self->type & SOCKET_HAS_SSL) {
    lua_pushstring(L, ((struct SSLSocket*)self)->peer);
  } else {
    struct sockaddr_in client_addr = {0};
    int addr_len = sizeof(client_addr);
    if (getpeername(self->fds[0], (struct sockaddr*)&client_addr, &addr_len) < 0)
      return luaL_error(L, "unable to get peer address: %s", strerror(errno));
    lua_pushstring(L, inet_ntoa(client_addr.sin_addr));
  }
  return 1;
}

static int f_socket_connect(lua_State* L) {
  const char* protocol = luaL_checkstring(L, 1);
  const char* hostname = luaL_checkstring(L, 2);
  int port = luaL_checkinteger(L, 3);
  struct hostent *host = gethostbyname(hostname);
  struct sockaddr_in dest_addr = {0};
  if (!host)
    return luaL_error(L, "can't resolve hostname %s", hostname);
  int s = socket(AF_INET, SOCK_STREAM, 0);
  fcntl(s, F_SETFL, O_NONBLOCK);
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(port);
  dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);
  if (connect(s, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) == -1) {
    if (errno != EINPROGRESS && errno != EAGAIN) {
      close(s);
      return luaL_error(L, "can't connect to host %s [%s] on port %d", hostname, inet_ntoa(dest_addr.sin_addr), port);
    }
  }
  struct Socket* socket = lua_newsocket(L, SOCKET_TYPE_CLIENT);
  socket->fds[0] = s;
  return 1;
}


static int f_socket_pipe(lua_State* L) {
  struct Socket* socket_a = lua_newsocket(L, SOCKET_TYPE_PIPE);
  struct Socket* socket_b = lua_newsocket(L, SOCKET_TYPE_PIPE);
  lua_pushvalue(L, -1);
  lua_setmetatable(L, -3);
  lua_setmetatable(L, -2);
  int fds[2];
  if (pipe(fds))
    return luaL_error(L, "can't create pipe: %s", strerror(errno));
  fcntl(fds[0], F_SETFL, O_NONBLOCK);
  fcntl(fds[1], F_SETFL, O_NONBLOCK);
  socket_a->fds[0] = fds[0]; // read
  socket_b->fds[1] = fds[1]; // write
  if (pipe(fds))
    return luaL_error(L, "can't create pipe: %s", strerror(errno));
  fcntl(fds[0], F_SETFL, O_NONBLOCK);
  fcntl(fds[1], F_SETFL, O_NONBLOCK);
  socket_b->fds[0] = fds[0]; // read
  socket_a->fds[1] = fds[1]; // write
  return 2;
}


static int f_socket_close(lua_State* L) {
  struct Socket* self = lua_touserdata(L, 1);
  switch (self->type & SOCKET_TYPE_MASK) {
    case SOCKET_TYPE_CLOSED: break;
    case SOCKET_TYPE_SERVER:
    case SOCKET_TYPE_CLIENT:
    case SOCKET_TYPE_FILE:
      if (self->type & SOCKET_HAS_SSL) {
        struct SSLSocket* ssl = (struct SSLSocket*)self;
        if (ssl->handshook) {
          mbedtls_pk_free(&ssl->private_key);
          mbedtls_x509_crt_free(&ssl->certificate);
          mbedtls_ctr_drbg_free(&ssl->ctr_drbg);
          mbedtls_entropy_free(&ssl->entropy);
        }
        mbedtls_net_free(&ssl->net_context);
        mbedtls_ssl_free(&ssl->ssl_context);
      } else {
        if (close(self->fds[0]))
          return luaL_error(L, "can't close socket fd %d: %s", self->fds[0], strerror(errno));
      }
      self->type = (self->type & ~SOCKET_TYPE_MASK) | SOCKET_TYPE_CLOSED;
    break;
    case SOCKET_TYPE_PIPE:
      if (close(self->fds[0]) || close(self->fds[1]))
        return luaL_error(L, "can't close socket fd %d %d: %s", self->fds[0], self->fds[1], strerror(errno));
    break;
  }
  return 0;
}

static int f_socket_handshake_certificate(void* context, mbedtls_ssl_context* ssl_context, const unsigned char* server_name, size_t server_name_length) {
  lua_State* L = (lua_State*)context;
  struct SSLSocket* client = lua_touserdata(L, 1);
  if (!client->handshook) {
    lua_pushlstring(L, server_name, server_name_length);
    if (lua_pcall(L, 1, 3, 0) != 0)
      return -1;
    const char* certificate_contents = lua_tostring(L, -3);
    const char* private_key_contents = lua_tostring(L, -2);
    const char* chain_contents = lua_tostring(L, -1);
    if (!certificate_contents || !private_key_contents) {
      lua_pushfstring(L, "returned no certificate or private key for '%s'", server_name);
      return -1;
    }
    mbedtls_x509_crt_init(&client->certificate);
    int ret = mbedtls_x509_crt_parse(&client->certificate, certificate_contents, strlen(certificate_contents) + 1);
    if (ret != 0)
      return lua_mbedtls_error(L, ret, "error parsing certificate for '%s'", server_name);
    mbedtls_pk_init(&client->private_key);
    ret = mbedtls_pk_parse_key(&client->private_key, private_key_contents, strlen(private_key_contents) + 1, NULL, 0, mbedtls_ctr_drbg_random, &client->ctr_drbg);
    if (ret != 0)
      return lua_mbedtls_error(L, ret, "error parsing private key for '%s'", server_name);
    client->handshook = 1;
  }
  return mbedtls_ssl_set_hs_own_cert(&client->ssl_context, &client->certificate, &client->private_key);
}

static int f_socket_handshake(lua_State* L) {
  struct SSLSocket* client = (struct SSLSocket*)lua_touserdata(L, 1);
  luaL_checktype(L, 2, LUA_TFUNCTION);
  mbedtls_ssl_conf_sni(&client->config, f_socket_handshake_certificate, L);
  int top = lua_gettop(L);
  int ret = mbedtls_ssl_handshake(&client->ssl_context);
  if (ret != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      if (client->handshook)
        return luaL_mbedtls_error(L, ret, "error handshaking");
      return lua_error(L);
    }
    return 0;
  }
  lua_pushboolean(L, 1);
  return 1;
}

static void my_debug(void *ctx, int level,
                     const char *file, int line,
                     const char *str)
{
    fprintf(stderr, "WAT\n");
    fprintf(stderr, "%s:%04d: %s", file, line, str);
    fflush(stderr);
}

static int f_socket_accept(lua_State* L) {
  struct Socket* self = lua_touserdata(L, 1);
  if ((self->type & SOCKET_TYPE_MASK) != SOCKET_TYPE_SERVER)
    return luaL_error(L, "can't accept on socket: not a server");

  if (self->type & SOCKET_HAS_SSL) {
    struct SSLSocket* server = ((struct SSLSocket*)self);
    struct SSLSocket* client = (struct SSLSocket*)lua_newsocket(L, SOCKET_TYPE_CLIENT | SOCKET_HAS_SSL);
    mbedtls_net_init(&client->net_context);
    size_t peer_size;
    int ret;
    if ((ret = mbedtls_net_accept(&server->net_context, &client->net_context, client->peer, sizeof(client->peer), &peer_size)) != 0) {
      if (ret == MBEDTLS_ERR_SSL_WANT_READ)
        return 0;
    }

    mbedtls_ctr_drbg_init(&client->ctr_drbg);
    mbedtls_ssl_init(&client->ssl_context);
    mbedtls_ssl_config_init(&client->config);
    mbedtls_ssl_config_defaults(&client->config, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_setup(&client->ssl_context, &client->config);
    const char *pers = "ssl_server";
    mbedtls_entropy_init(&client->entropy);
    ret = mbedtls_ctr_drbg_seed(&client->ctr_drbg, mbedtls_entropy_func, &client->entropy, (const unsigned char *) pers, strlen(pers));
    mbedtls_ssl_conf_rng(&client->config, mbedtls_ctr_drbg_random, &client->ctr_drbg);
    mbedtls_ssl_conf_dbg(&client->config, my_debug, stdout);
    mbedtls_ssl_set_bio(&client->ssl_context, &client->net_context, mbedtls_net_send, mbedtls_net_recv, NULL);
    mbedtls_net_set_nonblock(&client->net_context);
  } else {
    struct Socket* client = lua_newsocket(L, SOCKET_TYPE_CLIENT);
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    client->fds[0] = accept(self->fds[0], (struct sockaddr*)&addr, &addrlen);
    if (client->fds[0] < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;
      return luaL_error(L, "can't accept on socket: %s", strerror(errno));
    }
    fcntl(client->fds[0], F_SETFL, O_NONBLOCK);
  }
  return 1;
}


static int f_socket_write(lua_State* L) {
  struct Socket* client = lua_touserdata(L, 1);
  size_t len;
  const char* msg = luaL_checklstring(L, 2, &len);
  size_t offset = luaL_optinteger(L, 3, 0);
  int fd = client->fds[0];
  switch (client->type & SOCKET_TYPE_MASK) {
    case SOCKET_TYPE_FILE:
    case SOCKET_TYPE_SERVER:
      return luaL_error(L, "invalid socket type");
    case SOCKET_TYPE_PIPE:
      fd = client->fds[1];
    case SOCKET_TYPE_CLIENT:
      if (client->type & SOCKET_HAS_SSL) {
        int written = mbedtls_ssl_write(&((struct SSLSocket*)client)->ssl_context, &msg[offset], len - offset);
        if (written < 0) {
          if (written != MBEDTLS_ERR_SSL_WANT_WRITE)
            return luaL_error(L, "can't write to socket: %s", strerror(errno));
          written = 0;
        }
        if (written < len) {
        }
        lua_pushinteger(L, written);
      } else {
        int written = write(fd, &msg[offset], len - offset);
        if (written < 0) {
          if (errno != EAGAIN && errno != EWOULDBLOCK)
            return luaL_error(L, "can't write to socket: %s", strerror(errno));
          written = 0;
        }
        if (written < len) {
        }
        lua_pushinteger(L, written);
      }
    break;
  }
  return 1;
}


static int f_socket_read(lua_State* L) {
  struct Socket* client = lua_touserdata(L, 1);
  int len = luaL_checkinteger(L, 2);
  if (len < 0)
    return luaL_error(L, "Requires a positive length.");
  int received = 0;
  char chunk[4096];
  luaL_Buffer buffer;
  luaL_buffinit(L, &buffer);
  while (received < len) {
    int to_receive = len - received;
    if (to_receive > sizeof(chunk))
      to_receive = sizeof(chunk);
    int chunk_length;
    if (client->type & SOCKET_HAS_SSL) {
      chunk_length = mbedtls_ssl_read(&((struct SSLSocket*)client)->ssl_context, chunk, to_receive);
      if (chunk_length < 0) {
        if (chunk_length == MBEDTLS_ERR_SSL_WANT_READ)
          break;
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 1;
      }
    } else {
      chunk_length = read(client->fds[0], chunk, to_receive);
      if (chunk_length < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
          break;
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 1;
      }
    }
    if (chunk_length == 0)
      break;
    luaL_addlstring(&buffer, chunk, chunk_length);
    received += chunk_length;
  }
  luaL_pushresult(&buffer);
  return 1;
}


static int f_system_ls(lua_State* L) {
  const char* path = luaL_checkstring(L, 1);
  DIR *dir = opendir(path);
  if (!dir)
    return luaL_error(L, "can't ls %s: %d", path, strerror(errno));
  lua_newtable(L);
  int i = 1;
  struct dirent *entry;
  while ( (entry = readdir(dir)) ) {
    if (strcmp(entry->d_name, "." ) == 0) { continue; }
    if (strcmp(entry->d_name, "..") == 0) { continue; }
    lua_pushstring(L, entry->d_name);
    lua_rawseti(L, -2, i);
    i++;
  }
  closedir(dir);
  return 1;
}


static int f_system_stat(lua_State* L) {
  const char *path = luaL_checkstring(L, 1);
  lua_newtable(L);
  struct stat s;
  int err = lstat(path, &s);
  char *abs_path = realpath(path, NULL);
  if (err || !abs_path) {
    lua_pushnil(L);
    lua_pushstring(L, strerror(errno));
    return 2;
  }
  lua_pushstring(L, abs_path); lua_setfield(L, -2, "abs_path");
  lua_pushvalue(L, 1); lua_setfield(L, -2, "path");
  if (S_ISLNK(s.st_mode)) {
    char buffer[PATH_MAX];
    ssize_t len = readlink(path, buffer, sizeof(buffer));
    if (len < 0)
      return 0;
    lua_pushlstring(L, buffer, len);
  } else
    lua_pushnil(L);
  lua_setfield(L, -2, "symlink");
  if (S_ISLNK(s.st_mode))
    err = stat(path, &s);
  if (err)
    return 1;
  lua_pushinteger(L, s.st_mtime); lua_setfield(L, -2, "modified");
  lua_pushinteger(L, s.st_size); lua_setfield(L, -2, "size");
  if (S_ISREG(s.st_mode)) {
    lua_pushstring(L, "file");
  } else if (S_ISDIR(s.st_mode)) {
    lua_pushstring(L, "dir");
  } else {
    lua_pushnil(L);
  }
  lua_setfield(L, -2, "type");
  return 1;
}


static mbedtls_entropy_context entropy_context;
static mbedtls_ctr_drbg_context drbg_context;
static mbedtls_x509_crt client_x509_certificate;
static mbedtls_ssl_config client_ssl_config;
static mbedtls_ssl_context client_ssl_context;


static int f_system_certs(lua_State* L) {
  const char* type = luaL_checkstring(L, 1);
  const char* path = luaL_checkstring(L, 2);
  int status;
  mbedtls_entropy_init(&entropy_context);
  mbedtls_ctr_drbg_init(&drbg_context);
  mbedtls_x509_crt_init(&client_x509_certificate);
  if ((status = mbedtls_ctr_drbg_seed(&drbg_context, mbedtls_entropy_func, &entropy_context, NULL, 0)) != 0)
    return luaL_mbedtls_error(L, status, "failed to setup mbedtls_x509");
  mbedtls_ssl_config_init(&client_ssl_config);
  status = mbedtls_ssl_config_defaults(&client_ssl_config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
  if (status)
    return luaL_mbedtls_error(L, status, "can't set ssl_config defaults");
  mbedtls_ssl_conf_max_version(&client_ssl_config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
  mbedtls_ssl_conf_min_version(&client_ssl_config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
  mbedtls_ssl_conf_authmode(&client_ssl_config, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_rng(&client_ssl_config, mbedtls_ctr_drbg_random, &drbg_context);
  mbedtls_ssl_conf_read_timeout(&client_ssl_config, 5000);
  if (strcmp(type, "system") == 0) {
    #if _WIN32
      assert(!client_certificate_chain);
      int client_certificate_chain_size = 16*1024;
      static char* client_certificate_chain = malloc(client_certificate_chain_size);
      int client_certificate_chain_offset = 0;
      HCERTSTORE hSystemStore = CertOpenSystemStore(0, TEXT("ROOT"));
      if (!hSystemStore)
        return luaL_error(L, "error getting system certificate store");
      PCCERT_CONTEXT pCertContext = NULL;
      while (1) {
        pCertContext = CertEnumCertificatesInStore(hSystemStore, pCertContext);
        if (!pCertContext)
          break;
        BYTE keyUsage[2];
        if (pCertContext->dwCertEncodingType & X509_ASN_ENCODING && (CertGetIntendedKeyUsage(pCertContext->dwCertEncodingType, pCertContext->pCertInfo, keyUsage, sizeof(keyUsage)) && (keyUsage[0] & CERT_KEY_CERT_SIGN_KEY_USAGE))) {
          DWORD size = 0;
          CryptBinaryToString(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, CRYPT_STRING_BASE64HEADER, NULL, &size);
          if (size + client_certificate_chain_offset >= client_certificate_chain_size) {
            client_certificate_chain_size *= 2;
            client_certificate_chain = realloc(client_certificate_chain, client_certificate_chain_size);
          }
          CryptBinaryToString(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, CRYPT_STRING_BASE64HEADER, &client_certificate_chain[client_certificate_chain_offset], &size);
        }
      }
      CertCloseStore(hSystemStore, 0);
      if ((status = mbedtls_x509_crt_parse(&client_x509_certificate, client_certificate_chain, client_certificate_chain_offset)) != 0)
        return luaL_mbedtls_error(L, status, "mbedtls_x509_crt_parse_file failed to parse CA certificate %s", path);
    #else
      return luaL_error(L, "can't use system certificates on non-windows");
    #endif
  } else {
    if ((status = mbedtls_x509_crt_parse_file(&client_x509_certificate, path)) != 0)
      return luaL_mbedtls_error(L, status, "mbedtls_x509_crt_parse_file failed to parse CA certificate %s", path);
  }
  mbedtls_ssl_conf_ca_chain(&client_ssl_config, &client_x509_certificate, NULL);
  return 0;
}

static lua_State* sas_newstate();

/*** Thread Specific ***/
static int f_thread_transfer(lua_State* from, int index, lua_State* to)  {
  switch (lua_type(from, index)) {
    case LUA_TSTRING: { size_t len; const char* str = lua_tolstring(from, index, &len);  lua_pushlstring(to, str, len); } break;
    case LUA_TNONE: case LUA_TNIL:  lua_pushnil(to); break;
    case LUA_TNUMBER:  lua_pushnumber(to, lua_tonumber(from, index));  break;
    case LUA_TBOOLEAN: lua_pushboolean(to, lua_toboolean(from, index)); break;
    case LUA_TLIGHTUSERDATA: lua_pushlightuserdata(to, lua_touserdata(from, index)); break;
    default: return luaL_error(from, "can't transfer type"); break;
  }
}

static int f_thread_writer(lua_State* L, const void* p, size_t sz,  void* ud) {
  luaL_addlstring((luaL_Buffer*)ud, p, sz);
  return 0;
}

static const char* f_thread_reader(lua_State* T, void* L, size_t* size) {
  if (lua_isnil(((lua_State*)L), -1)) return NULL;
  const char* str = lua_tolstring((lua_State*)L, -1, size);
  lua_pushnil((lua_State*)L);
  return str;
}

static void* f_thread_callback(void* T) {
  return (void*)(long long)lua_pcall((lua_State*)T, lua_gettop(T) - 1, 1, 0);
}

int f_thread_new(lua_State* L) {
  int arguments = lua_gettop(L) - 1;
  lua_State* T = sas_newstate();
  luaL_Buffer buffer;
  luaL_buffinit(L, &buffer);
  lua_pushvalue(L, 1);
  int err = lua_dump(L, f_thread_writer, &buffer, 0);
  if (err)
    return luaL_error(L, "can't parse thread callback: %d", err);
  luaL_pushresult(&buffer);
  lua_load(T, f_thread_reader, L, "thread", "b");
  lua_pop(L, 1);
  for (int i = 0; i < arguments; ++i)
    f_thread_transfer(L, i + 2, T);
  pthread_t thread;
  int status = pthread_create(&thread, NULL, f_thread_callback, T);
  lua_newtable(L);
  lua_pushlightuserdata(L, T);
  lua_setfield(L, -2, "state");
  lua_pushlightuserdata(L, (void*)thread);
  lua_setfield(L, -2, "thread");
  luaL_setmetatable(L, "Thread");
  return 1;
}


int f_thread_join(lua_State* L) {
  lua_getfield(L, 1, "thread");
  pthread_t thread = (pthread_t)lua_touserdata(L, -1);
  lua_getfield(L, 1, "state");
  lua_State* T = (lua_State*)lua_touserdata(L, -1);
  void* err = NULL;
  int status = pthread_join(thread, &err);
  if (status)
    lua_pushfstring(L, "error joining thread: %d", status);
  else if (err)
    lua_pushfstring(L, "error in thread: %s", lua_tostring(T, -1));
  if (status || err) {
    lua_close(T);
    lua_pushnil(L);
    lua_setfield(L, 1, "state");
    return lua_error(L);
  }
  f_thread_transfer(T, -1, L);
  return 1;
}

int f_thread_term(lua_State* L) {
  lua_getfield(L, 1, "thread");
  pthread_t thread = (pthread_t)lua_touserdata(L, -1);
  pthread_cancel(thread);
  lua_pop(L, 1);
  return f_thread_join(L);
}

int f_system_sleep(lua_State* L) {
  usleep(luaL_checknumber(L, 1) * 1000000);
  return 0;
}

static const luaL_Reg pending_lib[] = {
  { "new",       f_pending_new     },  // Creates a pending set which poll should be called on.
  { "add",       f_pending_add     },  // Adds an fd to the set.
  { "remove",    f_pending_remove  },  // Remvoes an fd from the set.
  { "__gc",      f_pending_close   },  // Closes the pending set.
  { "close",     f_pending_close   },  // Closes the pending set.
  { "poll",      f_pending_poll    },  // Blocking poll. Returns the fd that matches this event.
  { NULL,        NULL              }
};

static const luaL_Reg socket_lib[] = {
  { "__gc",      f_socket_close      },   // Calls close if relevant.
  { "listen",    f_socket_listen     },   // Creates a listening socket at the specified port and address, and protocol (SSL or not).
  { "connect",   f_socket_connect    },   // Creates a socket at the specified port and address, and protocol (SSL or not).
  { "pipe",      f_socket_pipe       },   // Returns two pipes for sending/receiving data not on an internet connection.
  { "peer",      f_socket_peer       },   // Returns the peer location of this socket.
  { "close",     f_socket_close      },   // Closes this socket.
  { "accept",    f_socket_accept     },   // Non-blocking accept.
  { "write",     f_socket_write      },   // Non-blocking write of N bytes.
  { "read",      f_socket_read       },   // Non-blocking read of N bytes.
  { "handshake", f_socket_handshake  },   // Non-blocking handshake. Returns true on handsahek completion.
  { NULL,        NULL              }
};

static const luaL_Reg thread_lib[] = {
  { "new",       f_thread_new        },   // Creates a new thread that runs the function specified.
  { "term",      f_thread_term       },   // Kills the thread in question.
  { "join",      f_thread_join       },   // Joins the thread gracefully back to the main program.
  { "__gc",      f_thread_term       },   // Kills the thread in question.
  { NULL,        NULL              }
};

static const luaL_Reg system_lib[] = {
  { "sleep",     f_system_sleep      },   // Sleeps for the specified amount of seconds.
  { "ls",        f_system_ls         },   // Returns an array of files.
  { "stat",      f_system_stat       },   // Returns a stat of the file.
  { "certs",     f_system_certs      },   // Sets up the SSL certificate store.
  { NULL,        NULL              }
};


#ifndef SAS_VERSION
  #define SAS_VERSION "unknown"
#endif

static int f_sleep(lua_State* L) {
  sleep(luaL_checkinteger(L, 1));
}

static lua_State* sas_newstate() {
  lua_State* L = luaL_newstate();
  luaL_openlibs(L);
  luaL_newmetatable(L, "Pending"); luaL_setfuncs(L, pending_lib, 0); lua_pushvalue(L, -1); lua_setfield(L, -2, "__index"); lua_setglobal(L, "Pending");
  luaL_newmetatable(L, "Socket"); luaL_setfuncs(L, socket_lib, 0); lua_pushvalue(L, -1); lua_setfield(L, -2, "__index"); lua_setglobal(L, "Socket");
  luaL_newmetatable(L, "Thread"); luaL_setfuncs(L, thread_lib, 0); lua_pushvalue(L, -1); lua_setfield(L, -2, "__index"); lua_setglobal(L, "Thread");
  lua_pushcfunction(L, f_sleep); lua_setglobal(L, "sleep");
  luaL_newlib(L, system_lib); lua_setglobal(L, "system");
  return L;
}

#ifdef SAS_STATIC
extern const char src_main_lua[];
extern unsigned int src_main_lua_len;
#endif
int main(int argc, char* argv[]) {
  sigaction(SIGPIPE, &(struct sigaction){SIG_IGN}, NULL);
  lua_State* L = sas_newstate();
  lua_newtable(L);
  for (int i = 0; i < argc; ++i) {
    lua_pushstring(L, argv[i]);
    lua_rawseti(L, -2, i+1);
  }
  lua_setglobal(L, "ARGV");
  lua_pushliteral(L, SAS_VERSION);
  lua_setglobal(L, "VERSION");
  #if _WIN32
    lua_pushliteral(L, "windows");
    lua_pushliteral(L, "\\");
  #else
    lua_pushliteral(L, "posix");
    lua_pushliteral(L, "/");
  #endif
  lua_setglobal(L, "PATHSEP");
  lua_setglobal(L, "PLATFORM");
  #ifndef SAS_STATIC
  lua_pushboolean(L, 1);
  lua_setglobal(L, "LIVE");
  if (luaL_loadfile(L, "src/main.lua") || lua_pcall(L, 0, 1, 0)) {
  #else
  lua_pushboolean(L, 0);
  lua_setglobal(L, "LIVE");
  if (luaL_loadbuffer(L, src_main_lua, src_main_lua_len, "main.lua") || lua_pcall(L, 0, 1, 0)) {
  #endif
    fprintf(stderr, "internal error when starting the application: %s\n", lua_tostring(L, -1));
    return -1;
  }
  int status = lua_tointeger(L, -1);
  lua_close(L);
  return status;
}

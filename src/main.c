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

#ifndef SAS_NO_SSL
  #include <openssl/ssl.h>
  #include <openssl/err.h>
#endif


#define MAX_EVENTS 1
#define MAX_RECV_BUFFER (16*1024)

struct SocketSet {
  int epollfd;
  struct epoll_event events[MAX_EVENTS];
};


static int socketset_new(lua_State *L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  int len = luaL_len(L, 1);
  lua_newtable(L);
  struct SocketSet* s = lua_newuserdata(L, sizeof(struct SocketSet));
  lua_setfield(L, -1, "set");
  s->epollfd = epoll_create1(0);
  if (s->epollfd == -1)
    return luaL_error(L, "can't accept on socket: %s", strerror(errno));
  for (int i = 1; i < len; ++i) {
    struct epoll_event ev;
    ev.events = EPOLLIN;
    lua_rawgeti(L, 1, i);
    luaL_checktype(L, -1, LUA_TTABLE);
    lua_getfield(L, -1, "socket");
    ev.data.fd = luaL_checkinteger(L, -1);
    lua_pop(L, 2);
    if (epoll_ctl(s->epollfd, EPOLL_CTL_ADD, ev.data.fd, &ev) == -1) {
      close(s->epollfd);
      return luaL_error(L, "can't add socket %d: %s", ev.data.fd, strerror(errno));
    }
  }
  luaL_setmetatable(L, "socketset");
  return 1;
}

 
static int socketset_poll(lua_State* L) {
  lua_getfield(L, 1, "set");
  struct SocketSet* s = lua_touserdata(L, -1);
  int nfds = epoll_wait(s->epollfd, s->events, MAX_EVENTS, -1);
  if (nfds == -1) 
    return luaL_error(L, "can't poll: %s", strerror(errno));
  lua_pushinteger(L, s->events[0].data.fd);
  lua_rawget(L, 1);
  return 1;
}


static int socketset_close(lua_State* L) {
  lua_getfield(L, 1, "set");
  struct SocketSet* s = lua_touserdata(L, -1);
  close(s->epollfd);
  return 1;
}


#ifndef SAS_NO_SSL
static int ssl_callback(SSL *ssl, int *al, void *L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ssl_backreference");
    lua_pushlightuserdata(L, SSL_get_SSL_CTX(ssl));
    lua_rawget(L, -2);
    lua_getfield(L, -1, "cb");
    lua_pushstring(L, SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name));
    lua_call(L, 1, 2);
    const char* certificate = luaL_checkstring(L, -2);
    const char* private_key = luaL_checkstring(L, -1);
    if (!lua_isstring(L, -2) || SSL_CTX_use_certificate_file(SSL_get_SSL_CTX(ssl), lua_tostring(L, -1), SSL_FILETYPE_PEM) <= 0) 
      return SSL_TLSEXT_ERR_ALERT_FATAL;
    if (!lua_isstring(L, -1) || SSL_CTX_use_PrivateKey_file(SSL_get_SSL_CTX(ssl), lua_tostring(L, -1), SSL_FILETYPE_PEM) <= 0 )
      return SSL_TLSEXT_ERR_ALERT_FATAL;
    return SSL_TLSEXT_ERR_OK;
}
#endif 

static int socket_listen(lua_State* L) {
  lua_newtable(L);
  struct sockaddr_in addr = { .sin_family = AF_INET };
  addr.sin_addr.s_addr = inet_addr(luaL_checkstring(L, 1));
  addr.sin_port = htons(luaL_checkinteger(L, 2));
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0)
    luaL_error(L, "can't open socket: %s", strerror(errno));
  if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    close(s);
    luaL_error(L, "can't bind socket: %s", strerror(errno));
  }
  if (listen(s, 1) < 0) {
    close(s);
    luaL_error(L, "can't listen on socket: %s", strerror(errno));
  }
  lua_pushinteger(L, s);
  lua_setfield(L, -2, "socket");
  #ifndef SAS_NO_SSL 
  if (lua_type(L, 3) == LUA_TTABLE) {
    lua_getfield(L, 3, "ssl");
    if (lua_toboolean(L, -1)) {
      const SSL_METHOD *method = TLS_server_method();
      SSL_CTX* ctx = SSL_CTX_new(method);
      if (!ctx) {
        close(s);
        return luaL_error(L, "can't open ssl context on socket: %s", ERR_error_string(ERR_get_error(), NULL));
      }
      lua_pushlightuserdata(L, ctx);
      lua_setfield(L, -3, "ctx");
      if (lua_isfunction(L, -1)) {
        lua_pushvalue(L, -1);
        lua_setfield(L, -3, "cb");
        lua_getfield(L, LUA_REGISTRYINDEX, "ssl_backreference");
        lua_pushlightuserdata(L, ctx);
        lua_pushvalue(L, -4);
        lua_settable(L, -3);
        SSL_CTX_set_tlsext_servername_arg(ctx, L);
        SSL_CTX_set_tlsext_servername_callback(ctx, ssl_callback);
      } else if (lua_istable(L, -1)) {
        lua_rawgeti(L, -1, 1);
        lua_rawgeti(L, -2, 2);
        if (!lua_isstring(L, -2) || SSL_CTX_use_certificate_file(ctx, lua_tostring(L, -2), SSL_FILETYPE_PEM) <= 0) {
          close(s);
          SSL_CTX_free(ctx);
          return luaL_error(L, "can't use ssl certificate file on socket: %s", ERR_error_string(ERR_get_error(), NULL));
        }
        if (!lua_isstring(L, -1) || SSL_CTX_use_PrivateKey_file(ctx, lua_tostring(L, -1), SSL_FILETYPE_PEM) <= 0 ) {
          close(s);
          SSL_CTX_free(ctx);
          return luaL_error(L, "can't use ssl private key file on socket: %s", ERR_error_string(ERR_get_error(), NULL));
        }
      } else {
        close(s);
        SSL_CTX_free(ctx);
        return luaL_error(L, "can't parse ssl options; invalid structure");
      }
    }
    lua_pop(L, 1);
  }
  #endif 
  luaL_setmetatable(L, "socket");
  return 1;
}


static int socket_close(lua_State* L) {
  lua_getfield(L, 1, "socket");
  int s = lua_tointeger(L, -1);
  lua_getfield(L, 1, "ctx");
  #ifndef SAS_NO_SSL
  if (!lua_isnil(L, -1))
    SSL_CTX_free(lua_touserdata(L, -1));
  lua_getfield(L, 1, "ssl");
  if (!lua_isnil(L, -1)) {
    SSL* ssl = lua_touserdata(L, -1);
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }
  #endif
  close(s);
  return 0;
}


static int socket_accept(lua_State* L) {
  struct sockaddr_in addr;
  socklen_t addrlen = sizeof(addr);
  lua_getfield(L, 1, "socket");
  int server = lua_tointeger(L, -1);
  int client = accept(server, (struct sockaddr*)&addr, &addrlen);
  if (client < 0)
    return luaL_error(L, "can't accept on socket: %s", strerror(errno));
  lua_newtable(L);
  lua_pushinteger(L, client);
  lua_setfield(L, -2, "socket");
  luaL_setmetatable(L, "socket");
  lua_getfield(L, 1, "ctx");
  #ifndef SAS_NO_SSL
  if (!lua_isnil(L, -1)) {
    SSL *ssl = SSL_new(lua_touserdata(L, -1));
    SSL_set_fd(ssl, client);
    if (SSL_accept(ssl) <= 0) {
      SSL_shutdown(ssl);
      SSL_free(ssl);
      close(client);
      return luaL_error(L, "can't ssl accept on socket: %s", ERR_error_string(ERR_get_error(), NULL));
    }
    lua_setfield(L, -2, "ssl");
  }
  #endif
  lua_pop(L, 1);
  return 1;
}


static int socket_send(lua_State* L) {
  size_t len;
  const char* msg = luaL_checklstring(L, 2, &len);
  lua_getfield(L, 1, "socket");
  lua_getfield(L, 1, "ssl");
  int s, written = lua_tointeger(L, 1);
  if (lua_isnil(L, -1)) {
    written = send(s, msg, len, 0);
    if (written < 0)
      return luaL_error(L, "can't send to socket: %s", strerror(errno));
  } else {
    #ifndef SAS_NO_SSL
    SSL* ssl = lua_touserdata(L, -1);
    written = SSL_write(ssl, msg, len);
    if (written < 0)
      return luaL_error(L, "can't send to ssl socket: %d", SSL_get_error(ssl, written));
    #endif
  }
  lua_pushinteger(L, written);
  return 1;
}


static int socket_recv(lua_State* L) {
  int len = luaL_checkinteger(L, 2);
  lua_getfield(L, 1, "socket");
  int s = lua_tointeger(L, -1);
  lua_getfield(L, 1, "ssl");
  char buffer[MAX_RECV_BUFFER];
  if (lua_isnil(L, -1)) {
    len = recv(s, buffer, len, 0);
    if (len < 0)
      return luaL_error(L, "can't recv from socket: %s", strerror(errno));
  } else {
    #ifndef SAS_NO_SSL
    SSL* ssl = lua_touserdata(L, -1);
    len = SSL_read(ssl, buffer, len);
    if (len < 0)
      return luaL_error(L, "can't recv from ssl socket: %d", SSL_get_error(ssl, len));
    #endif
  }
  lua_pushlstring(L, buffer, len);
  return 1;
}


#ifndef SAS_VERSION
  #define SAS_VERSION "unknown"
#endif


static const luaL_Reg socketset_lib[] = {
  { "new",       socketset_new   },  // Creates a socket set which poll should be called on.
  { "__gc",      socketset_close },  // Closes the socket set.
  { "poll",      socketset_poll  },  // Blocking poll. Returns the socket that matches this event.
  { NULL,        NULL            }
};

static const luaL_Reg socket_lib[] = {
  { "__gc",      socket_close  },   // Calls close if relevant.
  { "listen",    socket_listen },   // Creates a listening socket at the specified port and address, and protocol (SSL or not).
  { "close",     socket_close  },   // Closes this socket.
  { "accept",    socket_accept },   // Non-blocking accept.
  { "send",      socket_send   },   // Sends the specified amount of bytes on the socket.
  { "recv",      socket_recv   },   // Receives the max amount of bytes on the socket.
  { NULL,        NULL }
};

extern const char src_main_lua[];
extern unsigned int src_main_lua_len;
int main(int argc, char* argv[]) {
  lua_State* L = luaL_newstate();
  luaL_openlibs(L);
  luaL_newmetatable(L, "socketset"); luaL_setfuncs(L, socketset_lib, 0); lua_setglobal(L, "socketset");
  luaL_newmetatable(L, "socket"); luaL_setfuncs(L, socket_lib, 0); lua_setglobal(L, "socket");
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
  #if SAS_LIVE
  if (luaL_loadfile(L, "src/main.lua") || lua_pcall(L, 0, 1, 0)) {
  #else
  if (luaL_loadbuffer(L, src_lpm_lua, src_lpm_lua_len, "main.lua") || lua_pcall(L, 0, 1, 0)) {
  #endif
    fprintf(stderr, "internal error when starting the application: %s\n", lua_tostring(L, -1));
    return -1;
  }
  int status = lua_tointeger(L, -1);
  lua_close(L);
  return status;
}
                                                                     

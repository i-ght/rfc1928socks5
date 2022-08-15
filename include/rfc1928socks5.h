#ifndef _RFC1928SOCKS5_H_
#define _RFC1928SOCKS5_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

struct Socks5Client
{
    int socket_fd;
    struct sockaddr address;
};

typedef struct Socks5Client* (*AcquireResourceSocks5Client)(void);
typedef void (*RelenquishResourceSocks5Client)(const struct Socks5Client* socks5_client);

struct Socks5ServerCfg
{
    AcquireResourceSocks5Client acquire_client_resources;
    RelenquishResourceSocks5Client relenquish_client_resources;
};

struct Socks5Server
{
    int epoll_fd;
    int listener_socket_fd;
    struct Socks5ServerCfg cfg;
};

int socks5_server_construct(
    struct Socks5Server* server,
    struct Socks5ServerCfg* cfg
);

#endif
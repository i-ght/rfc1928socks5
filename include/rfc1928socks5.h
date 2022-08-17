#ifndef _RFC1928SOCKS5_H_
#define _RFC1928SOCKS5_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stddef.h>

#include "hashpipe.h"

#define CLIENT_RECV_TEMP_SPACE 8192

enum Socks5ClientPhase
{
    SOCKS5_CONN_PHASE_ACCEPTING_CLIENT_CONNECTION,
    SOCKS5_CONN_PHASE_RECV_CLIENT_VERSION_CHOICE,
    SOCKS5_CONN_PHASE_RECV_CLIENT_VERSION_CHOICE_METHODS_ARRAY
};

struct Socks5Client
{
    enum Socks5ClientPhase phase;
    int socket_fd;
    struct sockaddr address;
    socklen_t addr_len;
    size_t expect_to_recv;
    ptrdiff_t recvd;
    char temp_recv_space[CLIENT_RECV_TEMP_SPACE];
};


typedef struct Socks5Client* (*AcquireResourceSocks5Client)(void);
typedef void (*RelenquishResourceSocks5Client)(struct Socks5Client* socks5_client);

struct Socks5Server;

struct Socks5ServerCfg
{
    AcquireResourceSocks5Client acquire_client_resources;
    RelenquishResourceSocks5Client relenquish_client_resources;
    void (*trip_client_connected_event)(struct Socks5Server* server, const int socks5_client_socket_fd) ;
    void (*trip_client_disconnected_event)(struct Socks5Server* server, const int socks5_client_socket_fd);
    struct addrinfo listener_address;
};

struct Socks5Server
{
    int listener_socket_fd;
    struct Socks5ServerCfg cfg;
    struct Hash clients;
    void* data;
};

int socks5server_construct(
    struct Socks5Server* server,
    const struct Socks5ServerCfg* cfg
);

int socks5server_begin_listening(
    const struct Socks5Server* socks5_server,
    const int back_log
);

int socks5server_proc_io_events(
    struct Socks5Server* socks5_server,
    const int readable_socket_fds[],
    const size_t readable_count
);

int socks5server_proc_io_events(
    struct Socks5Server* socks5_server,
    const int readable_socket_fds[],
    const size_t readable_count
);

#endif
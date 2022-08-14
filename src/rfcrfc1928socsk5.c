#include "rfc1928socks5.h"

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <poll.h>
#include <sys/epoll.h>
#include <limits.h>


#define SOCKS_PORT_CSTR "1080"

enum {SOCKS_PORT=1080};
enum {ZERO=0};
enum {OK=0,ERR=-1};
enum {MAX_CONNECTIONS=UINT8_MAX};

struct ClientHello
{
    uint8_t version;
    uint8_t method_count;
    uint8_t methods[8];
};


static int close_fd_ret_err(
    const int fd)
{
    if (ERR == close(fd)) {
        /*ignored*/
#if DEBUG
        static char errMsg[UCHAR_MAX] = {0};
        const int _ = 
            snprintf(
                errMsg,
                sizeof(errMsg),
                "close fd '%d' error",
                fd
            );
        perror(errMsg);
#endif
    }

    return ERR;
}

struct SocketOptionPair
{
    const int name;
    const void* value;
    const size_t value_occupied_space;
};

#define ARRAY_COUNT(a) (sizeof(a)/sizeof(*a))

static int construct_socks5_listener_socket(
    const struct addrinfo* server_info)
{
    const int socket_fd =
        socket(
            server_info->ai_family,
            server_info->ai_socktype,
            server_info->ai_protocol
        );
    if (ERR == socket_fd) {
        return ERR;
    }

    static const int yes = 1;
    
    static const struct SocketOptionPair options[] = {
        { .name =  SO_REUSEADDR,
          .value = &yes,
          .value_occupied_space = sizeof(yes) },
        { .name = SOCK_NONBLOCK,
          .value = &yes,
          .value_occupied_space = sizeof(yes) }
    };

    for (size_t i = ZERO; i < ARRAY_COUNT(options); i++) {
        if (ERR ==
            setsockopt(
                socket_fd,
                SOL_SOCKET,
                options[i].name,
                options[i].value,
                options[i].value_occupied_space
            )
        ) {
            return ERR;
        };

    }

    if (ERR == 
        bind(
            socket_fd,
            server_info->ai_addr,
            server_info->ai_addrlen
        )
    ) {
        return close_fd_ret_err(socket_fd);
    }

    return socket_fd;
}

int socks5server_construct(
    struct Socks5Server* socks5_server,
    const struct addrinfo* server_info)
{
    const int listener_socket_fd =
        construct_socks5_listener_socket(server_info);

    if (ERR == listener_socket_fd) {
        return ERR;
    }
    
    socks5_server->listener_socket_fd = listener_socket_fd;

    const int epoll_fd =
        epoll_create1(0);

    if (ERR == epoll_fd) {
        return ERR;
    }

    socks5_server->epoll_fd = epoll_fd;

    struct epoll_event event = {
        .data = { .fd = listener_socket_fd },
        .events = EPOLLIN | EPOLLET
    };
    if (ERR == 
        epoll_ctl(
            epoll_fd,
            EPOLL_CTL_ADD,
            listener_socket_fd,
            &event
        )
    ) {
        return ERR;
    } 

    return OK;
}

int socks5_begin_listening(
    const int sock5_socket_fd,
    const int back_log)
{
    if (ERR ==
        listen(
            sock5_socket_fd,
            back_log
        )
    ) {
        return ERR;
    }

    return OK;
}

int socks5_poll_proc_events(
    struct Socks5Server* socks5_server)
{
    enum {MAX_EVENTS=23, TIMEOUT=-1};
    static struct epoll_event events[MAX_EVENTS] = {0};


    const int fds =
        epoll_wait(
            socks5_server->epoll_fd,
            &events,
            MAX_EVENTS,
            TIMEOUT
        );
    if (ERR == fds) {
        return ERR;
    }

    for (size_t i = 0; i < fds; i++) {
        
    }

    return 0;
}

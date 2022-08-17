#include <stdlib.h>
#include <sys/epoll.h>
#include "rfc1928socks5.h"


enum {OK=0,ERR=-1};

static struct Socks5Client* alloc_socks5_client(void)
{
    struct Socks5Client* ret =
        calloc(
            1,
            sizeof(struct Socks5Client)
        );
    if (NULL == ret) {
        exit(1);
        return NULL;
    }

    return ret;
}

static void free_socks5_client(
    struct Socks5Client* socks5_client)
{
    free(socks5_client);
}

#define ARRAY_COUNT(a) (sizeof(a)/sizeof(*a))

void epoll_add_client(
    struct Socks5Server* socks5_server,
    const int socks5_client_socket_fd)
{
    struct epoll_event client_events_of_interest = {
        .events = EPOLLIN | EPOLLRDHUP | EPOLLET,
        .data = {.fd = socks5_client_socket_fd }
    };
    if (ERR == 
        epoll_ctl(
            *(int*)socks5_server->data,
            EPOLL_CTL_ADD,
            socks5_client_socket_fd,
            &client_events_of_interest
        )
    ) {
        exit(1);
    }

}

/*
    const int epoll_fd =
        epoll_create1(0);

    if (ERR == epoll_fd) {
        return ERR;
    }


    epoll_ctl(
        socks5_server->epoll_fd,
        EPOLL_CTL_DEL,
        socks5_client->socket_fd,
        NULL
    ),

        struct epoll_event client_events_of_interest = {
        .data = { .fd = socks5_client->socket_fd },
        .events = EPOLLIN | EPOLLET | EPOLLRDHUP
    };
    


    struct epoll_event listener_events_of_interest = {
        .data = { .fd = listener_socket_fd },
        .events = EPOLLIN | EPOLLET
    };
    if (ERR == 
        epoll_ctl(
            epoll_fd,
            EPOLL_CTL_ADD,
            listener_socket_fd,
            &listener_events_of_interest
        )
    ) {
        return ERR;
    }
*/



int main(void)
{    
    const int epoll_fd =
        epoll_create1(0);
    if (ERR == epoll_fd) {
        return ERR;
    }
    static struct Socks5Server socks5_server = {0};

    socks5_server.data = (void*)&epoll_fd;
    
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE
    };
    struct addrinfo *server_info = NULL;
    
    if (ERR == getaddrinfo(NULL, "1080", &hints, &server_info)) {
        return ERR;
    }
    
    struct Socks5ServerCfg cfg = {
        .acquire_client_resources = alloc_socks5_client,
        .relenquish_client_resources = free_socks5_client,
        .trip_client_connected_event = epoll_add_client,
        .trip_client_disconnected_event = NULL,
        .listener_address = *server_info,
    };

    int sequence[] = {
        socks5server_construct(
            &socks5_server,
            &cfg
        ),
        socks5server_begin_listening(
            &socks5_server,
            1024
        )
    };
    for (size_t i = 0; i < ARRAY_COUNT(sequence); i++) {
        if (ERR == sequence[i]) {
            return ERR;
        }
    }

    struct epoll_event listener_events_of_interest = {
        .events = EPOLLIN | EPOLLET,
        .data = { . fd = socks5_server.listener_socket_fd },
    };
    if (ERR ==
        epoll_ctl(
            epoll_fd,
            EPOLL_CTL_ADD,
            socks5_server.listener_socket_fd,
            &listener_events_of_interest
        )
    ) {
        return ERR;
    }

    enum {MAX_EVENTS=23};
    struct epoll_event events[MAX_EVENTS] = {0};
    for (;;) {
        const int active_fds =
            epoll_wait(
                epoll_fd,
                &events[0],
                MAX_EVENTS,
                23232
            );
        if (ERR == active_fds) {
            return ERR;
        }

        int read_fd_cnt = 0;
        int read_fds[MAX_EVENTS] = {0};
        for (ptrdiff_t i = 0; i < active_fds; i++) {
            const struct epoll_event* ev = &events[i];
            if (ev->events & EPOLLIN) {
                read_fds[read_fd_cnt++] = ev->data.fd; 
            }
    
        }

        if (ERR ==
            socks5server_proc_io_events(
                &socks5_server,
                read_fds,
                read_fd_cnt
            )
        ) {
            return ERR;
        }
    }

    freeaddrinfo(server_info);
    return 0;
}
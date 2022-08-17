#include "rfc1928socks5.h"

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <poll.h>
#include <sys/epoll.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>

#define SOCKS_PORT_CSTR "1080"

#define ARRAY_COUNT(a) (sizeof(a)/sizeof(*a))

enum {SOCKS_PORT=1080};
enum {ZERO=0};
enum {OK=0,ERR=-1};
enum {MAX_CONNECTIONS=UINT8_MAX};
enum {CLIENT_VERSION_CHOICE_LENGTH=2};
enum {MAX_METHODS=8};

struct ClientHello
{
    uint8_t version;
    uint8_t method_count;
    uint8_t methods[MAX_METHODS];
};

static int set_socket_nonblocking(
    const int socket_fd)
{

    int flags = fcntl(socket_fd, F_GETFL, 0);
    if (-1 == fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK)) {
        return ERR;
    }
    return OK;
}


static int close_socket(
    const int socket_fd)
{
    const int ret = close(socket_fd);
    if (ERR == ret) {
#if DEBUG
        perror("close socket");
        assert(OK == ret);
#endif
    }
    return ret;
}

static int try_close_socket_then_ret_arg(
    const int socket_fd,
    const int ret)
{
    const int _ignored =
        close_socket(socket_fd);
    return ret;
}


static int destruct_client_socket(
    struct Socks5Client* socks5_client)
{
    const int ret =
        close_socket(socks5_client->socket_fd);
    return ret;
}

static int try_destruct_client_socket_ret_arg(
    struct Socks5Client* socks5_client,
    const int ret)
{
    return try_close_socket_then_ret_arg(
        socks5_client->socket_fd,
        ret
    );
}

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
    

    if (ERR ==
        setsockopt(
            socket_fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            &yes,
            sizeof(yes)
        )
    ) {
        return try_close_socket_then_ret_arg(
            socket_fd,
            ERR
        );
    };

    if (ERR == set_socket_nonblocking(socket_fd)) {
        return try_close_socket_then_ret_arg(
            socket_fd,
            ERR
        );
    }

    if (ERR == 
        bind(
            socket_fd,
            server_info->ai_addr,
            server_info->ai_addrlen
        )
    ) {
        return try_close_socket_then_ret_arg(
            socket_fd,
            ERR
        );
    }

    return socket_fd;
}

int socks5server_begin_listening(
    const struct Socks5Server* socks5_server,
    const int back_log)
{
    if (ERR ==
        listen(
            socks5_server->listener_socket_fd,
            back_log
        )
    ) {
        return ERR;
    }

    return OK;
}

static int accept_awaiting_connection(
    struct Socks5Server* socks5_server,
    struct Socks5Client* socks5_client)
{
    struct sockaddr client_address = {0};
    socklen_t addr_len = 0;

    const int client_socket_fd =
        accept(
            socks5_server->listener_socket_fd,
            &client_address,
            &addr_len
        );

    if (ERR == client_socket_fd) {
        socks5_client->socket_fd = ERR;
        return ERR;
    }

    static const int yes = 1;

    if (ERR == set_socket_nonblocking(client_socket_fd)) {
        return try_destruct_client_socket_ret_arg(
            socks5_client,
            ERR
        );
    }
        
    socks5_client->socket_fd = client_socket_fd;
    socks5_client->address = client_address;
    socks5_client->addr_len = addr_len;

    return OK;
}


struct Socks5Client* socks5_server_acquire_client_resources(
    struct Socks5Server* socks5_server)
{
    return socks5_server->cfg.acquire_client_resources();
}

static void socks5_server_relinquish_client_resources(
    struct Socks5Server* socks5_server,
    struct Socks5Client* socks5s_client)
{
    return socks5_server->cfg.relenquish_client_resources(socks5s_client);
}

static void rmclient_destructconn_relenquish_resources(
    struct Socks5Server* socks5_server,
    struct Socks5Client* socks5_client)
{
    int ret = OK;
    if (NULL != 
        hash_add(
            &socks5_server->clients,
            (const char*)&socks5_client->socket_fd,
            sizeof(socks5_client->socket_fd),
            NULL
        )
    ) {
        ret = ERR;
    } 

    if (ERR == destruct_client_socket(socks5_client) && ret != ERR) {
        ret = ERR;
    }

    socks5_server->cfg.trip_client_disconnected_event(
        socks5_server,
        socks5_client->socket_fd
    );
    
    socks5_client->socket_fd = ZERO;

    socks5_server_relinquish_client_resources(
        socks5_server,
        socks5_client
    );

    assert(ret == OK);
}

enum ProcConnConsequence
{
    PROC_CONN_OK,
    PROC_CONN_BLOCKED,
    PROC_CONN_ERR
};

static enum ProcConnConsequence proc_new_connection_event(
    struct Socks5Server* socks5_server)
{
    //TODO: Loop

    struct Socks5Client* socks5_client =
        socks5_server_acquire_client_resources(
            socks5_server);

    assert(NULL != socks5_client);

    const void* _ = 
        memset(
            socks5_client,
            ZERO,
            sizeof(struct Socks5Client)
        );

    if (ERR == 
        accept_awaiting_connection(
            socks5_server,
            socks5_client
        )
    ) {

        socks5_server_relinquish_client_resources(
            socks5_server,
            socks5_client
        );

        switch (errno) {
            case EAGAIN:
                return PROC_CONN_BLOCKED;
            default:
                return ERR;
        }
    }

    if (NULL != 
        hash_add(
            &socks5_server->clients,
            (const char*)&socks5_client->socket_fd,
            sizeof(socks5_client->socket_fd),
            socks5_client
        )
    ) {
        int ret = 
            try_destruct_client_socket_ret_arg(
                socks5_client,
                ERR
            );

        socks5_server_relinquish_client_resources(
            socks5_server,
            socks5_client
        );

        return ret;
    }

    socks5_client->phase = SOCKS5_CONN_PHASE_RECV_CLIENT_VERSION_CHOICE;
    socks5_client->expect_to_recv = /* 2 */ CLIENT_VERSION_CHOICE_LENGTH;

    socks5_server->cfg.trip_client_connected_event(
            socks5_server,
            socks5_client->socket_fd
    );

    return OK;
}

static int proc_client_ver_choice_first2bytes(
    struct Socks5Server* socks5_server,
    struct Socks5Client* socks5_client)
{
    assert(CLIENT_VERSION_CHOICE_LENGTH == socks5_client->recvd);
    char* recv_buff = socks5_client->temp_recv_space;
    const uint8_t ver = recv_buff[0];
    const uint8_t method_count = recv_buff[1];
    if (method_count > MAX_METHODS) {
        return ERR;
    }

    return OK;
}

static int client_recv(
    struct Socks5Client* socks5_client,
    const char* buffer,
    const size_t buff_space)
{
    assert(
        buff_space <= sizeof(socks5_client->temp_recv_space)
    );
    
    int total_read = 0;
    int read = 0;
    while (ERR != (
        read = 
            recv(
                socks5_client->socket_fd,
                (void*)buffer,
                buff_space,
                0
            )
    ) && (total_read += read) < buff_space) {

        enum {RECV_TEMP_SPACE_LASTI=sizeof(socks5_client->temp_recv_space) - 1};

        const ptrdiff_t index = socks5_client->recvd;

        if (index > RECV_TEMP_SPACE_LASTI) {
            return ERR;
        }

        const ptrdiff_t space_left =
            &socks5_client->temp_recv_space[RECV_TEMP_SPACE_LASTI] - &socks5_client->temp_recv_space[index];

        if (read > space_left) {
            return ERR;
        }

        char* dest = &socks5_client->temp_recv_space[index];
        
        const void* _ =
            memmove(
                dest,
                buffer,
                read
            );

        socks5_client->recvd += read;
    }

    switch (errno) {
        case EAGAIN:
            break;
              
        default:
#if DEBUG
            perror("recv err");
#endif
            return ERR;
    }

    return total_read;
}

/*
   The client connects to the server, and sends a version
   identifier/method selection message:

                   +----+----------+----------+
                   |VER | NMETHODS | METHODS  |
                   +----+----------+----------+
                   | 1  |    1     | 1 to 255 |
                   +----+----------+----------+
    recv first two bytes first, then receive the length of the array.
*/

enum RecvMsgConsequence
{
    RECV_MSG_OK,
    RECV_MSG_PARTIAL,
    RECV_MSG_ERR = ERR
};


static enum RecvMsgConsequence recv_msg_from_client(
    struct Socks5Server* socks5_server,
    struct Socks5Client* socks5_client,
    const size_t size_of_msg)
{
    enum {TMP_SPACE=8192};
    assert(size_of_msg < TMP_SPACE);

    char tmp[TMP_SPACE] = {0};
    
    const ptrdiff_t left_to_recv =
        size_of_msg - socks5_client->recvd;

    assert(left_to_recv > 0);

    const int read =
        client_recv(
            socks5_client,
            &tmp[0],
            left_to_recv
        );
    if (ERR == read) {
#if DEBUG
        perror("recv err");
#endif
        return RECV_MSG_ERR;
    }

    if (size_of_msg == socks5_client->recvd) {
        socks5_client->recvd = ZERO;
        return RECV_MSG_OK;
    } else if (socks5_client->recvd > size_of_msg) {
        return RECV_MSG_ERR;
    }
    
    return RECV_MSG_PARTIAL;
}

static int recv_data_from_client_connection(
    struct Socks5Server* socks5_server,
    struct Socks5Client* socks5_client)
{

phase_change:
    switch (socks5_client->phase) {
        case SOCKS5_CONN_PHASE_RECV_CLIENT_VERSION_CHOICE:
            switch (
                recv_msg_from_client(
                    socks5_server,
                    socks5_client,
                    CLIENT_VERSION_CHOICE_LENGTH
                )
            ) {
                case RECV_MSG_PARTIAL:
                    return OK;
                case RECV_MSG_OK: {
                    enum {ONE=1};
                    socks5_client->expect_to_recv = socks5_client->temp_recv_space[ONE];
                    socks5_client->phase = SOCKS5_CONN_PHASE_RECV_CLIENT_VERSION_CHOICE_METHODS_ARRAY;
                    goto phase_change; /*new phase*/
                }
                case RECV_MSG_ERR:
                    return ERR;
            }

        case SOCKS5_CONN_PHASE_RECV_CLIENT_VERSION_CHOICE_METHODS_ARRAY:

            return ERR;
        case SOCKS5_CONN_PHASE_ACCEPTING_CLIENT_CONNECTION:
        
            return ERR;


    }

    return OK;
}

static int proc_client_readable_event(
    struct Socks5Server* socks5_server,
    struct Socks5Client* socks5_client)
{

    if (ERR == 
        recv_data_from_client_connection(
            socks5_server,
            socks5_client
        )
    ) {
        

        rmclient_destructconn_relenquish_resources(
            socks5_server,
            socks5_client
        );

        return ERR;
    }
    
    return OK;
}

static int proc_socket_readable_event(
    struct Socks5Server* socks5_server,
    const int socket_fd)
{
    if (socks5_server->listener_socket_fd == socket_fd) {
        enum ProcConnConsequence ret = {0};
        do {
            ret = proc_new_connection_event(
                socks5_server
            );
        } while (ret == PROC_CONN_OK);
        switch (ret) {
            case PROC_CONN_BLOCKED:
            case PROC_CONN_OK:
                return OK;
            case PROC_CONN_ERR:
                return ERR;
        }
    } 

    struct Socks5Client* socks5_client =
        hash_lookup(
            &socks5_server->clients,
            (const char*)&socket_fd,
            sizeof(socket_fd)
        );
    if (NULL == socks5_client) {
        return ERR;
    }
    
    return proc_client_readable_event(
        socks5_server,
        socks5_client
    );

}


int socks5server_proc_io_events(
    struct Socks5Server* socks5_server,
    const int readable_socket_fds[],
    const size_t readable_count)
{
    for (ptrdiff_t i = 0; i < readable_count; i++) {
        const int readable_socket_fd =
            readable_socket_fds[i];

        if (ERR ==
            proc_socket_readable_event(
                socks5_server,
                readable_socket_fd
            )
        ) {
            return ERR;
        }
        
    }

    return OK;
}


int socks5server_construct(
    struct Socks5Server* socks5_server,
    const struct Socks5ServerCfg* cfg)
{

    socks5_server->listener_socket_fd = -1;
    socks5_server->cfg = *cfg;

    const int listener_socket_fd =
        construct_socks5_listener_socket(
            &socks5_server->cfg.listener_address
        );

    if (ERR == listener_socket_fd) {
        return ERR;
    }
    
    socks5_server->listener_socket_fd = listener_socket_fd;

    hash_init(&socks5_server->clients);

    return OK;
}
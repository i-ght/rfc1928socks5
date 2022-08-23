#include "rfc1928socks5.h"

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>

#define SOCKS_PORT_CSTR "1080"

#define ARRAY_COUNT(a) (sizeof(a)/sizeof(*a))

enum {SOCKS_PORT=1080};
enum {ZERO=0};
enum {OK=0,ERR=-1};
enum {MAX_CONNECTIONS=UINT8_MAX};
enum {CLIENT_VERSION_CHOICE_LENGTH=2};


enum AdvancePhaseConsequence
{
    ADVANCE_PHASE_OK,
    ADVANCE_PHASE_IOBLOCKED_AGAIN,
    ADVANCE_PHASE_ERR = -1
};

enum TryParseConsequence
{
    TRY_PARSE_OK,
    TRY_PARSE_UNEXPECTED_END_OF_INPUT,
    TRY_PARSE_ERR = -1
};

static enum TryParseConsequence try_parse_client_request(
    const char data[],
    const size_t space,
    struct ClientRequest* req)
{
    enum {MIN_SPACE=9};
    if (space < MIN_SPACE) {
        return TRY_PARSE_UNEXPECTED_END_OF_INPUT;
    }

    const uint8_t ver = data[0];

    enum {FIVE=5};
    if (FIVE != ver) {
        return TRY_PARSE_ERR;
    }

    const enum Socks5RequestCmd cmd = data[1];

    if (SOCKS5_REQUEST_CMD_CONNECT != cmd) {
        return TRY_PARSE_ERR;
    }

    const enum Socks5AddrType addr_type = data[3];

    switch (addr_type) {
        case SOCKS5_ADDR_TYPE_IPV4:
            break;
        case SOCKS5_ADDR_TYPE_DOMAINNAME:
            break;
        case SOCKS5_ADDR_TYPE_IPV6:
            break;

        default: return TRY_PARSE_ERR;
    }

    return TRY_PARSE_OK;    
}

static enum TryParseConsequence try_parse_client_hello(
    const char data[],
    const size_t space,
    struct ClientHello* client_hello)
{
    enum {MIN_SPACE=3};
    if (space < MIN_SPACE) {
        return TRY_PARSE_UNEXPECTED_END_OF_INPUT;
    }

    enum {FIVE=5};
    const int version = data[0];
    if (FIVE != version) {
        return TRY_PARSE_ERR;
    }

    const int method_count = data[1];
    if (method_count > sizeof(client_hello->methods)) {
        return TRY_PARSE_ERR;
    }

    const size_t methods_array_space =
        space - 2;
    if (methods_array_space < method_count) {
        return TRY_PARSE_UNEXPECTED_END_OF_INPUT;
    }

    if (NULL != client_hello) {
        const void* _ =
            memmove(
                client_hello->methods,
                &data[2],
                method_count
            );
        client_hello->version = version;
        client_hello->method_count = method_count;
    }
    
    return TRY_PARSE_OK;
}

static int set_socket_nonblocking(
    const int socket_fd)
{

    int flags = fcntl(socket_fd, F_GETFL, 0);
    if (O_NONBLOCK & flags) {
        return OK;
    }
    if (OK !=
        fcntl(
            socket_fd,
            F_SETFL,
            flags | O_NONBLOCK
        )
    ) {
        return ERR;
    }
    return OK;
}


static int close_socket(
    const int socket_fd)
{
    const int ret = close(socket_fd);
    if (OK != ret) {
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
        close_socket(socks5_client->inbound_socket_fd);
    return ret;
}

static int try_destruct_client_socket_ret_arg(
    struct Socks5Client* socks5_client,
    const int ret)
{
    return try_close_socket_then_ret_arg(
        socks5_client->inbound_socket_fd,
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

    if (OK !=
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

    if (OK != set_socket_nonblocking(socket_fd)) {
        return try_close_socket_then_ret_arg(
            socket_fd,
            ERR
        );
    }

    if (OK != 
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
    if (OK !=
        listen(
            socks5_server->listener_socket_fd,
            back_log
        )
    ) {
        return ERR;
    }

    return OK;
}

static int init_client(
    struct Socks5Server* socks5_server,
    struct Socks5Client* socks5_client,
    const int client_socket_fd,
    struct sockaddr* client_address,
    const socklen_t addr_len)
{
    if (OK != set_socket_nonblocking(client_socket_fd)) {
        return try_destruct_client_socket_ret_arg(
            socks5_client,
            ERR
        );
    }
        
    socks5_client->inbound_socket_fd = client_socket_fd;
    socks5_client->address = *client_address;
    socks5_client->addr_len = addr_len;
    socks5_client->status = RECVING_SOCKS5_REQUEST;
    socks5_client->phase = SOCKS5_CLIENT_PHASE_BEGIN_RECVING_CLIENT_VERSION_CHOICE_METHODS_ARRAY_REQ;
    return OK;
}

static int accept_awaiting_connection(
    struct Socks5Server* socks5_server,
    struct sockaddr* client_address,
    socklen_t* addr_len)
{
    const int client_socket_fd =
        accept(
            socks5_server->listener_socket_fd,
            client_address,
            addr_len
        );

    return client_socket_fd;
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

static int client_destruct(
    struct Socks5Server* socks5_server,
    struct Socks5Client* socks5_client)
{
    int ret = OK;
    const void* hash_value =
        hash_add(
            &socks5_server->clients,
            (const char*)&socks5_client->inbound_socket_fd,
            sizeof(socks5_client->inbound_socket_fd),
            NULL
        );
    if (socks5_client != 
        hash_value
    ) {
        ret = ERR;
    }

    if (OK != 
        socks5_server->cfg.unsub_all_socket_events(
            socks5_server,
            socks5_client->inbound_socket_fd
        )
    ) {
        ret = ERR;
    } 

    if (OK != destruct_client_socket(socks5_client) && ret != ERR) {
        ret = ERR;
    }

    socks5_client->inbound_socket_fd = ZERO;

    socks5_server_relinquish_client_resources(
        socks5_server,
        socks5_client
    );

    return ret;
}

static enum AdvancePhaseConsequence destruct_client_ret_phase_err(
    struct Socks5Server* socks5_server,
    struct Socks5Client* socks5_client)
{
    const int _ignored = 
        client_destruct(
            socks5_server,
            socks5_client
        );
    
    return ADVANCE_PHASE_ERR;
}

static enum AdvancePhaseConsequence proc_new_connection_event(
    struct Socks5Server* socks5_server)
{

    struct sockaddr client_addr = {0};
    socklen_t addr_len = 0;
    const int client_socket_fd =
        accept_awaiting_connection(
            socks5_server,
            &client_addr,
            &addr_len
        );
    if (ERR == 
        client_socket_fd
    ) {
        if (EAGAIN == errno) {
            return ADVANCE_PHASE_IOBLOCKED_AGAIN;
        }

        return ADVANCE_PHASE_ERR;
    }

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

    if (OK !=
        init_client(
            socks5_server,
            socks5_client,
            client_socket_fd,
            &client_addr,
            addr_len
        )
    ) {
        return destruct_client_ret_phase_err(
            socks5_server,
            socks5_client
        );
    }

    if (NULL != 
        hash_add(
            &socks5_server->clients,
            (const char*)&socks5_client->inbound_socket_fd,
            sizeof(socks5_client->inbound_socket_fd),
            socks5_client
        )
    ) {
        return destruct_client_ret_phase_err(
            socks5_server,
            socks5_client
        );
    }

    return socks5_server->cfg.sub_to_socket_read_activity_event(
            socks5_server,
            socks5_client->inbound_socket_fd
    ) 
    == OK 
    ? ADVANCE_PHASE_OK 
    : ADVANCE_PHASE_ERR;
}

static int send_what_may(
    const int socket_fd,
    const void* space,
    const size_t zero_point,
    const size_t time,
    bool *blocked_eagain) 
{
    assert(zero_point < time);

    const ptrdiff_t last_i = time - 1;
    
    ptrdiff_t i = zero_point;
    const ptrdiff_t total_amount_of_space_to_send = time - i;
    
    int total_sent = 0;

    for (;;) {
        if (total_sent >= total_amount_of_space_to_send) {
            return total_sent;
        }

        const size_t remaining_time = time - i;
        const int sent =
            send(
                socket_fd,
                &space[i],
                remaining_time,
                ZERO
            );
        if (sent == ZERO) {
            return total_sent;
        }
        if (sent == ERR && errno == EAGAIN) {
            if (NULL != blocked_eagain) {
                *blocked_eagain = true;
            }
            return total_sent;
        } else if (sent == ERR) {
            return ERR;
        }

        i += sent;
        total_sent += sent;
    }
}

static bool client_write_blocked_and_need_noti_on_writable(
    const struct Socks5Client* socks5_client)
{
    return socks5_client->inbound_write_subscribed_socket_fd > 0
        && socks5_client->io.to_send > 0;
}

static int client_send_whatmayof_iobuf(
    struct Socks5Server* socks5_server,
    struct Socks5Client* socks5_client)
{
    const int max = socks5_client->io.to_send;
    enum {SIZE_OF_SEND_SPACE=sizeof(socks5_client->io.send_space)};

    bool blocked_eagain = false;
    const int sent = 
        send_what_may(
            socks5_client->inbound_socket_fd,
            socks5_client->io.send_space,
            socks5_client->io.sent,
            socks5_client->io.to_send,
            &blocked_eagain
        );
    if (ERR == sent) {
        return ERR;
    }

    socks5_client->io.sent += sent;
    socks5_client->io.to_send -= sent;

    if (blocked_eagain) {

        if (client_write_blocked_and_need_noti_on_writable(socks5_client)) {
            const int duplicated = dup(socks5_client->inbound_socket_fd);
            if (ERR == duplicated) {
                return ERR;
            }
            if (OK !=
                socks5_server->cfg.sub_to_socket_write_activity_event(
                    socks5_server,
                    duplicated
                )
            ) {
                const int _ = close_socket(duplicated);
                return ERR;
            }
            socks5_client->inbound_write_subscribed_socket_fd = duplicated;
        } else if (ZERO == socks5_client->io.to_send) {
            if (OK !=
                socks5_server->cfg.unsub_to_socket_write_activity_event(
                    socks5_server,
                    socks5_client->inbound_socket_fd
                )
            ) {
                return ERR;
            }
            socks5_client->io.sent = ZERO;
            
            if (socks5_client->inbound_write_subscribed_socket_fd > 0) {
                if (OK != close_socket(socks5_client->inbound_write_subscribed_socket_fd)) {
                    return ERR;
                }
                socks5_client->inbound_write_subscribed_socket_fd = ERR;
            }
        }

    }

    return OK;
}

static int recv_what_may(
    const int socket_fd,
    void* space,
    const size_t zero_point,
    const size_t time,
    bool* end_of_stream)
{
    assert(zero_point < time);

    const ptrdiff_t last_i = time - 1;
    
    ptrdiff_t i = zero_point;
    const size_t total_amount_of_space_to_recv = time - i;

    int total_read = 0;

    for (;;) {
        if (total_read >= total_amount_of_space_to_recv) {
            return total_read;
        }

        const size_t remaining_time = time - i;
        const int read =
            recv(
                socket_fd,
                &space[i],
                remaining_time,
                ZERO
            );
        if (ZERO == read) {
            if (NULL != end_of_stream) {
                *end_of_stream = true;
            }
            return total_read;
        }

        if (ERR == read && errno == EAGAIN) {
            return total_read;
        } else if (ERR == read) {
            return ERR;
        }

        i += read;
        total_read += read;
    }
}

static int client_recv_whatmayof_iobuff(
    struct Socks5Client* socks5_client)
{    
    enum {RECV_TEMP_SPACE_LASTI=sizeof(socks5_client->io.recv_space) - 1};
    enum {B=sizeof(socks5_client->io.recv_space)};

    ptrdiff_t index = socks5_client->io.recvd;

    if (index > RECV_TEMP_SPACE_LASTI) {
        return ERR;
    }

    ptrdiff_t space_remaining =
        &socks5_client->io.recv_space[RECV_TEMP_SPACE_LASTI] - &socks5_client->io.recv_space[index];

    if (space_remaining <= 0) {
        return ERR;
    }

    bool end_of_stream = false;
    const int read =
        recv_what_may(
            socks5_client->inbound_socket_fd,
            socks5_client->io.recv_space,
            socks5_client->io.recvd,
            sizeof(socks5_client->io.recv_space),
            &end_of_stream
        );

    if (ERR == read || end_of_stream) {
        return ERR;
    }

    socks5_client->io.recvd += read;

    return OK;
}

static int server_choose_auth_method(
    const struct ClientHello* client_hello,
    int* choice)
{
    for (ptrdiff_t i = 0; i < client_hello->method_count; i++) {
        const uint8_t method =
            client_hello->methods[i];
        if (ZERO == method) {
            *choice = ZERO;
            return OK;
        }
    }
    return ERR;
}


static int client_set_sendiobuf(
    struct Socks5Client* socks5_client,
    const char* space,
    const size_t time)
{
    enum {MAX_TIME=sizeof(socks5_client->io.send_space)};

    if (time >= MAX_TIME) {
        return ERR;
    }
    const void* _ =
        memmove(
            socks5_client->io.send_space,
            space,
            time
        );

    socks5_client->io.sent = ZERO;
    socks5_client->io.to_send = time;

    return OK;
}

static enum AdvancePhaseConsequence
server_choose_auth_method_and_send(
    struct Socks5Server* socks5_server,
    struct Socks5Client* socks5_client)
{
    struct ClientHello* client_hello =
        &socks5_client->current_request.client_hello;
    
    int choice = 0;
    if (OK !=
        server_choose_auth_method(
            client_hello,
            &choice
        )
    ) {
        return ERR;
    }

/*
   The server selects from one of the methods given in METHODS, and
   sends a METHOD selection message:

                         +----+--------+
                         |VER | METHOD |
                         +----+--------+
                         | 1  |   1    |
                         +----+--------+
*/
    enum {TWO=2};
    char tmp[TWO] = {0x05, choice};

    if (OK !=
        client_set_sendiobuf(
            socks5_client,
            tmp,
            TWO
        )
    ) {
        return ERR;
    }

    return client_send_whatmayof_iobuf(
        socks5_server,
        socks5_client
    )
    != OK
    ? ADVANCE_PHASE_ERR
    : ADVANCE_PHASE_OK;
}

static enum AdvancePhaseConsequence search_client_recvbuff_for_req(
    struct Socks5Server* socks5_server,
    struct Socks5Client* socks5_client)
{
    if (socks5_client->io.recvd < 9) {
        return ADVANCE_PHASE_IOBLOCKED_AGAIN;
    }

    const char* recv_space =
        socks5_client->io.recv_space;
    
    switch (
        try_parse_client_request(
            socks5_client->io.recv_space,
            socks5_client->io.recvd,
            NULL
        )
    ) {
        case TRY_PARSE_OK:
            return ADVANCE_PHASE_OK;
        case TRY_PARSE_UNEXPECTED_END_OF_INPUT:
            return ADVANCE_PHASE_IOBLOCKED_AGAIN;
        case TRY_PARSE_ERR: default:
            return ADVANCE_PHASE_ERR;
    }
}

static enum AdvancePhaseConsequence
search_client_recvbuff_for_hello(
    struct Socks5Server* socks5_server,
    struct Socks5Client* socks5_client)
{    
    switch (
        try_parse_client_hello(
            socks5_client->io.recv_space,
            socks5_client->io.recvd,
            NULL
        )
    ) {
        case TRY_PARSE_OK:
            return ADVANCE_PHASE_OK;
        case TRY_PARSE_UNEXPECTED_END_OF_INPUT:
            return ADVANCE_PHASE_IOBLOCKED_AGAIN;
        default:
        case TRY_PARSE_ERR:
            return ADVANCE_PHASE_ERR;
    }
}


static int shift_phase(
    struct Socks5Server* socks5_server,
    struct Socks5Client* socks5_client)
{

phase_change:
    switch (socks5_client->phase) {
/*
    The client connects to the server, and sends a version 
    identifier/method selection message:

            +----+----------+----------+
            |VER | NMETHODS | METHODS  |
            +----+----------+----------+
            | 1  |    1     | 1 to 255 |
            +----+----------+----------+
*/
        case SOCKS5_CLIENT_PHASE_BEGIN_RECVING_CLIENT_VERSION_CHOICE_METHODS_ARRAY_REQ:
        case SOCKS5_CLIENT_PHASE_AWAITING_EVENT_RECVD_CLIENT_VERSION_CHOICE_METHODS_ARRAY_REQ:
            switch (
                search_client_recvbuff_for_hello(
                    socks5_server,
                    socks5_client
                )
            ) {
                case ADVANCE_PHASE_OK:
                    socks5_client->io.recvd = 0;
                    socks5_client->status = SENDING_SOCKS5_RESPONSE;
                    socks5_client->phase = SOCKS5_CLIENT_PHASE_BEGIN_SENDING_AUTH_METHOD_CHOICE_RESP;
                    goto phase_change;
                case ADVANCE_PHASE_IOBLOCKED_AGAIN:
                    socks5_client->phase = SOCKS5_CLIENT_PHASE_AWAITING_EVENT_RECVD_CLIENT_VERSION_CHOICE_METHODS_ARRAY_REQ;
                    return OK;
                case ADVANCE_PHASE_ERR: default:
                    return ERR;
            } 
/*
   The server selects from one of the methods given in METHODS, and
   sends a METHOD selection message:

                         +----+--------+
                         |VER | METHOD |
                         +----+--------+
                         | 1  |   1    |
                         +----+--------+
*/
        case SOCKS5_CLIENT_PHASE_BEGIN_SENDING_AUTH_METHOD_CHOICE_RESP:
            switch (
                server_choose_auth_method_and_send(
                    socks5_server,
                    socks5_client
                )
            ) {
                case ADVANCE_PHASE_OK:
                    socks5_client->status = RECVING_SOCKS5_REQUEST;
                    socks5_client->phase = SOCKS5_CLIENT_PHASE_RECV_REQUEST;
                    return OK;
                case ADVANCE_PHASE_IOBLOCKED_AGAIN:
                    socks5_client->phase = SOCKS5_CLIENT_PHASE_AWAITING_EVENT_SENT_AUTH_METHOD_CHOICE_RESP;
                    return OK;
                case ADVANCE_PHASE_ERR: default:
                    return ERR;
            }
        
        case SOCKS5_CLIENT_PHASE_AWAITING_EVENT_SENT_AUTH_METHOD_CHOICE_RESP:
            if (ZERO == socks5_client->io.to_send) {
                socks5_client->status = RECVING_SOCKS5_REQUEST;
                socks5_client->phase = SOCKS5_CLIENT_PHASE_RECV_REQUEST;
                return OK;
            }
            return OK;
/*
   The SOCKS request is formed as follows:

        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

     Where:

          o  VER    protocol version: X'05'
          o  CMD
             o  CONNECT X'01'
             o  BIND X'02'
             o  UDP ASSOCIATE X'03'
          o  RSV    RESERVED
          o  ATYP   address type of following address
             o  IP V4 address: X'01'
             o  DOMAINNAME: X'03'
             o  IP V6 address: X'04'
          o  DST.ADDR       desired destination address
          o  DST.PORT desired destination port in network octet
             order

   The SOCKS server will typically evaluate the request based on source
   and destination addresses, and return one or more reply messages, as
   appropriate for the request type.

*/
        case SOCKS5_CLIENT_PHASE_RECV_REQUEST:
            switch (
                search_client_recvbuff_for_req(
                    socks5_server,
                    socks5_client
                )
            ) {

            }
            return ERR;

        default:
            return ERR;
    }
}

static int client_recv_data_advance_phase(
    struct Socks5Server* socks5_server,
    struct Socks5Client* socks5_client)
{
    const int consequence =
        client_recv_whatmayof_iobuff(socks5_client);
    if (ERR == consequence) {
        return ERR;
    }

    return shift_phase(
        socks5_server,
        socks5_client
    );
}

static int proc_listener_pending_connections(
    struct Socks5Server* socks5_server)
{
    enum AdvancePhaseConsequence conseq = {0};
    int accepted = 0;
    do {
        conseq = proc_new_connection_event(
            socks5_server
        );
        if (ADVANCE_PHASE_OK == conseq) {
            accepted++;
        }
    } while (conseq == ADVANCE_PHASE_OK);

    switch (conseq) {
        case ADVANCE_PHASE_OK:
        case ADVANCE_PHASE_IOBLOCKED_AGAIN:
            if (ZERO == accepted) {
                return ERR;
            }

            return OK;
        default:
        case ADVANCE_PHASE_ERR:
            return ERR;
    }


}

static int proc_socket_writable_event(
    struct Socks5Server* socks5_server,
    const int socket_fd)
{
    struct Socks5Client* socks5_client =
        hash_lookup(
            &socks5_server->clients,
            (const char*)&socket_fd,
            sizeof(socket_fd)
        );
    if (NULL == socks5_client) {
        return ERR;
    }

    const int sent =
        client_send_whatmayof_iobuf(
            socks5_server,
            socks5_client
        );
    if (ERR == sent) {
        return ERR;
    }

    return shift_phase(
        socks5_server,
        socks5_client
    );
}

static int proc_socket_readable_event(
    struct Socks5Server* socks5_server,
    const int socket_fd)
{
    if (socks5_server->listener_socket_fd == socket_fd) {
        return proc_listener_pending_connections(socks5_server);
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

    return client_recv_data_advance_phase(
        socks5_server,
        socks5_client
    );
}


int socks5server_proc_io_events(
    struct Socks5Server* socks5_server,
    struct FdEventNotification event_notis[],
    const size_t event_noti_count)
{

    static int err_sock_fds[64];
    size_t err_i = 0;
    for (ptrdiff_t i = 0; i < event_noti_count; i++) {
        const struct FdEventNotification* noti =
            &event_notis[i];

        const bool readable = (noti->events_of_occurrence & FDIOEVENT_READABLE) > 0;
        const bool writable = (noti->events_of_occurrence & FDIOEVENT_WRITABLE) > 0;

        if (readable) {
            if (OK !=
                proc_socket_readable_event(
                    socks5_server,
                    noti->fd_of_interest
                )
            ) {
                err_sock_fds[i++] = err_i;
            }
        }

        if (writable) {
            if (OK !=
                proc_socket_writable_event(
                    socks5_server,
                    noti->fd_of_interest
                )
            ) {
                err_sock_fds[i++] = err_i;
            }
        }

        if (ZERO == err_i) {
            continue;
        }

        return ERR;

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
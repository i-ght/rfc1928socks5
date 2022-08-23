#ifndef _RFC1928SOCKS5_H_
#define _RFC1928SOCKS5_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>


#include "hashpipe.h"

#define CLIENT_TEMP_SPACE 8192

enum Socks5RequestReply
{
    SOCKS5_OK = 0,
    SOCKS5_ERROR,
    SOCKS5_ERROR_CONNECTION_TO_REMOTE_HOST_FORBIDDEN,
    SOCKS5_ERROR_NETWORK_UNREACHABLE,
    SOCKS5_ERROR_HOST_UNREACHABLE,
    SOCKS5_ERROR_CONNECTION_REFUSED,
    SOCKS5_ERROR_TTL_EXPIRED,
    SOCKS5_ERROR_CMD_NOT_SUPPORTED,
    SOCKS5_ERROR_ADDR_TYPE_NOT_SUPPORTED
};

enum Socks5ClientPhase
{
    SOCKS5_CLIENT_PHASE_BEGIN_RECVING_CLIENT_VERSION_CHOICE_METHODS_ARRAY_REQ,
    SOCKS5_CLIENT_PHASE_AWAITING_EVENT_RECVD_CLIENT_VERSION_CHOICE_METHODS_ARRAY_REQ,
    SOCKS5_CLIENT_PHASE_BEGIN_SENDING_AUTH_METHOD_CHOICE_RESP,
    SOCKS5_CLIENT_PHASE_AWAITING_EVENT_SENT_AUTH_METHOD_CHOICE_RESP,
    SOCKS5_CLIENT_PHASE_RECV_REQUEST
};

enum Socks5ReceivingRequestOrSendingResponse
{
    RECVING_SOCKS5_REQUEST,
    SENDING_SOCKS5_RESPONSE
};

struct ClientHello
{
    u_int8_t version;
    u_int8_t method_count;
    enum {MAX_METHODS=8};
    uint8_t methods[MAX_METHODS];
};

enum Socks5RequestCmd
{
    SOCKS5_REQUEST_CMD_CONNECT = 1,
    SOCKS5_REQUEST_CMD_BIND = 2,
    SOCKS5_REQUEST_CMD_UDPASSOSICATE = 3
};

enum Socks5AddrType
{
    SOCKS5_ADDR_TYPE_IPV4 = 1,
    SOCKS5_ADDR_TYPE_DOMAINNAME = 3,
    SOCKS5_ADDR_TYPE_IPV6 = 4,
};

union DestinationAddress
{
    enum {FOUR=4};
    char ipv4[FOUR];
    char domain_name[UINT8_MAX];
    enum {SIXTEEN=16};
    char ipv6[16];
};


struct ClientRequest
{
    u_int8_t version;
    enum Socks5RequestCmd cmd;
    uint8_t _reserved;
    enum Socks5AddrType addr_type;
    union DestinationAddress dst_addr;
    
    
};

union Socks5Request
{
    struct ClientHello client_hello;
};

struct IOBuffer
{
    char recv_space[CLIENT_TEMP_SPACE];
    char send_space[CLIENT_TEMP_SPACE];
    ptrdiff_t sent;
    ptrdiff_t to_send;
    ptrdiff_t recvd;
};

struct Socks5Client
{
    enum Socks5ClientPhase phase;
    enum Socks5ReceivingRequestOrSendingResponse status;
    int inbound_socket_fd;
    int inbound_write_subscribed_socket_fd;
    struct sockaddr address;
    socklen_t addr_len;
    struct IOBuffer io;
    union Socks5Request current_request;
};


typedef struct Socks5Client* (*AcquireResourceSocks5Client)(void);
typedef void (*RelenquishResourceSocks5Client)(struct Socks5Client* socks5_client);

struct Socks5Server;

struct Socks5ServerCfg
{
    AcquireResourceSocks5Client acquire_client_resources;
    RelenquishResourceSocks5Client relenquish_client_resources;
    int (*sub_to_socket_read_activity_event)(struct Socks5Server* server, const int socket_fd);
    int (*unsub_all_socket_events)(struct Socks5Server* server, const int socket_fd);
    int (*sub_to_socket_write_activity_event)(struct Socks5Server* server, const int socket_fd);
    int (*unsub_to_socket_write_activity_event)(struct Socks5Server* server, const int socket_fd);

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

enum FDIOEvent
{
    FDIOEVENT_READABLE = 1,
    FDIOEVENT_WRITABLE = 2
};


struct FdEventNotification
{
    int fd_of_interest;
    enum FDIOEvent events_of_occurrence;
};

int socks5server_proc_io_events(
    struct Socks5Server* socks5_server,
    struct FdEventNotification event_subscriptions[],
    const size_t readable_count
);

int socks5server_proc_io_events(
    struct Socks5Server* socks5_server,
    struct FdEventNotification event_notis[],
    const size_t event_noti_count
);

#endif
#ifndef _RFC1928SOCKS5_H_
#define _RFC1928SOCKS5_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "xpandarray.h"


struct Socks5Client
{
    int socket_fd;

};


struct Socks5Server
{
    int epoll_fd;
    int listener_socket_fd;
    struct XpandArray clients;
};


#endif
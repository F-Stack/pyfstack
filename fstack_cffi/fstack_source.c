#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/un.h>

#include <errno.h>

#include <ff_api.h>
#include <ff_epoll.h>

#define IOCTL_BUFSZ 1024
#define	SAS2SA(x)	((struct sockaddr *)(x))

void EPOLL_EV_SET_FD(struct epoll_event *ev, int fd) {
    ev->data.fd = fd;
}
int EPOLL_EV_GET_FD(struct epoll_event *ev) {
    return ev->data.fd;
}
void EPOLL_EV_SET_MASK(struct epoll_event *ev, int mask) {
    ev->events = mask;
}
int EPOLL_EV_GET_MASK(struct epoll_event *ev) {
    return ev->events;
}

int py_setblocking(int fd, int blocking) {
    int res = 0;
    int on = (blocking? 0: 1);
    /*
     * the O_NONBLOCK vlaue is not same on freebsd and linux,
     * so don't use fcntl
     */
    res = ff_ioctl(fd, FIONBIO, &on);
    return res;
}

struct cmsginfo {
    int level;
    int type;
    char* data;
};
/* Socket address */
typedef union sock_addr {
    struct sockaddr_in in;
    struct sockaddr_un un;
    struct sockaddr_in6 in6;
    struct sockaddr_storage storage;
} sock_addr_t;

int py_sendmsg(int fd, char* buffers[], int lenarr[], int nbuffers,
               char controlbuf[], int controllen,
               int flags, struct linux_sockaddr *addr, int addrlen)
{
    int res;
    struct msghdr msg = {0};
    struct iovec iov[nbuffers];
    for (int i = 0; i < nbuffers; ++i) {
        iov[i].iov_base  = buffers[i];
        iov[i].iov_len = lenarr[i];
    }
    msg.msg_name = addr;
    msg.msg_namelen = addrlen;
    msg.msg_iov = iov;
    msg.msg_iovlen = nbuffers;
    msg.msg_control = controlbuf;
    msg.msg_controllen = controllen;
    msg.msg_flags = flags;

    res = ff_sendmsg(fd, &msg, flags);
    return res;
}

int py_recvmsg(int fd, char buf[], int bufsize,
               char controlbuf[], int *controllen,
               int *flags, struct linux_sockaddr *addr, int *addrlen)
{
    int res;
    struct msghdr msg = {0};
    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = bufsize;

    msg.msg_name = addr;
    msg.msg_namelen = *addrlen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = controlbuf;
    msg.msg_controllen = *controllen;
    msg.msg_flags = *flags;
    res = ff_recvmsg(fd, &msg, *flags);

    *addrlen = msg.msg_namelen;
    *controllen = msg.msg_controllen;
    *flags = msg.msg_flags;

    return res;
}

int py_init_ipv6_addr(unsigned short port, char in6[16], struct sockaddr_in6 *addr) {
    addr->sin6_family = AF_INET6;
    addr->sin6_port = htons(port);
    memcpy(addr->sin6_addr.s6_addr, in6, 16);
    return 0;
}

int py_init_ipv4_addr(unsigned short port, char in4[4], struct sockaddr_in *addr) {
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    memcpy((&addr->sin_addr.s_addr), in4, 4);
    return 0;
}

int py_parse_ipv6_addr(unsigned short *port, char in6[16],struct sockaddr_in6 *addr) {
    *port = ntohs(addr->sin6_port);
    memcpy(in6, addr->sin6_addr.s6_addr, 16);
    return 0;
}

int py_parse_ipv4_addr(unsigned short *port, char in4[4],struct sockaddr_in *addr) {
    *port = ntohs(addr->sin_port);
    memcpy(in4, &addr->sin_addr.s_addr, 4);
    return 0;
}

// kqueue constants
#define EVFILT_READ     ...
#define EVFILT_WRITE    ...
#define EVFILT_AIO      ...    /* attached to aio requests */
#define EVFILT_VNODE    ...    /* attached to vnodes */
#define EVFILT_PROC     ...    /* attached to struct proc */
#define EVFILT_SIGNAL   ...    /* attached to struct proc */
#define EVFILT_TIMER    ...    /* timers */
#define EVFILT_FS          ...   /* filesystem events */
#define EVFILT_LIO         ...    /* attached to lio requests */
#define EVFILT_USER        ...    /* User events */
#define EVFILT_SYSCOUNT    ...

/* actions */
#define EV_ADD        ...        /* add event to kq (implies enable) */
#define EV_DELETE     ...        /* delete event from kq */
#define EV_ENABLE     ...        /* enable event */
#define EV_DISABLE    ...        /* disable event (not reported) */

/* flags */
#define EV_ONESHOT    ...        /* only report one occurrence */
#define EV_CLEAR      ...        /* clear event state after reporting */
#define EV_RECEIPT    ...        /* force EV_ERROR on success, data=0 */
#define EV_DISPATCH   ...        /* disable event after reporting */

#define EV_SYSFLAGS   ...        /* reserved by system */
#define EV_DROP       ...        /* note should be dropped */
#define EV_FLAG1      ...        /* filter-specific flag */

/* returned values */
#define EV_EOF        ...        /* EOF detected */
#define EV_ERROR      ...        /* error, data contains errno */

/*
  * data/hint flags/masks for EVFILT_USER, shared with userspace
  *
  * On input, the top two bits of fflags specifies how the lower twenty four
  * bits should be applied to the stored value of fflags.
  *
  * On output, the top two bits will always be set to NOTE_FFNOP and the
  * remaining twenty four bits will contain the stored fflags value.
  */
#define NOTE_FFNOP         ...        /* ignore input fflags */
#define NOTE_FFAND         ...        /* AND fflags */
#define NOTE_FFOR          ...        /* OR fflags */
#define NOTE_FFCOPY        ...        /* copy fflags */
#define NOTE_FFCTRLMASK    ...        /* masks for operations */
#define NOTE_FFLAGSMASK    ...

#define NOTE_TRIGGER       ...        /* Cause the event to be
                           triggered for output. */

/*
 * data/hint flags for EVFILT_{READ|WRITE}, shared with userspace
 */
#define NOTE_LOWAT        ...            /* low water mark */

/*
 * data/hint flags for EVFILT_VNODE, shared with userspace
 */
#define NOTE_DELETE    ...            /* vnode was removed */
#define NOTE_WRITE     ...            /* data contents changed */
#define NOTE_EXTEND    ...            /* size increased */
#define NOTE_ATTRIB    ...            /* attributes changed */
#define NOTE_LINK      ...            /* link count changed */
#define NOTE_RENAME    ...            /* vnode was renamed */
#define NOTE_REVOKE    ...            /* vnode access was revoked */

/*
 * data/hint flags for EVFILT_PROC, shared with userspace
 */
#define NOTE_EXIT         ...        /* process exited */
#define NOTE_FORK         ...        /* process forked */
#define NOTE_EXEC         ...        /* process exec'd */
#define NOTE_PCTRLMASK    ...        /* mask for hint bits */
#define NOTE_PDATAMASK    ...        /* mask for pid */

/* additional flags for EVFILT_PROC */
#define NOTE_TRACK        ...        /* follow across forks */
#define NOTE_TRACKERR     ...        /* could not track child */
#define NOTE_CHILD        ...        /* am a child process */

// epoll
#define EPOLL_CTL_ADD ...
#define EPOLL_CTL_DEL ...
#define EPOLL_CTL_MOD ...

// epoll event mask
#define EPOLLERR     ...
#define EPOLLET      ...
#define EPOLLHUP     ...
#define EPOLLIN      ...
#define EPOLLMSG     ...
#define EPOLLONESHOT ...
#define EPOLLOUT     ...
#define EPOLLPRI     ...
#define EPOLLRDBAND  ...
#define EPOLLRDNORM  ...
#define EPOLLWRBAND  ...
#define EPOLLWRNORM  ...

// poll
#define PIPE_BUF   ...
#define POLLERR    ...
#define POLLHUP    ...
#define POLLIN     ...
#define POLLMSG    ...
#define POLLNVAL   ...
#define POLLOUT    ...
#define POLLPRI    ...
#define POLLRDBAND ...
#define POLLRDNORM ...
#define POLLWRBAND ...
#define POLLWRNORM ...

#define FD_SETSIZE ...

#define IOCTL_BUFSZ ...

typedef unsigned int... u_int;
typedef unsigned short... u_short;
typedef int... socklen_t;

typedef struct {...;} fd_set;
typedef int... nfds_t;

struct timeval {
    long    tv_sec;         /* seconds */
    long    tv_usec;        /* microseconds */
};

typedef int... time_t;
struct timespec {
    time_t	tv_sec;		/* seconds */
    long	tv_nsec;	/* and nanoseconds */
};
struct pollfd {
    int   fd;         /* file descriptor */
    short events;     /* requested events */
    short revents;    /* returned events */
};

struct epoll_event {
    ...;
};

void EPOLL_EV_SET_FD(struct epoll_event *ev, int fd);
int EPOLL_EV_GET_FD(struct epoll_event *ev);
void EPOLL_EV_SET_MASK(struct epoll_event *ev, int mask);
int EPOLL_EV_GET_MASK(struct epoll_event *ev);

struct kevent {
    uintptr_t	ident;		/* identifier for this event */
    short		filter;		/* filter for event */
    u_short		flags;
    u_int		fflags;
    intptr_t	data;
    void		*udata;		/* opaque user data identifier */
};

struct sockaddr_in {
    unsigned short sin_port;
    ...;
};

struct sockaddr_in6 {
    unsigned short sin6_port;
    ...;
};

struct linux_sockaddr {
    short sa_family;
    char sa_data[14];
};


extern "Python" int loop_func(void *arg);

int ff_init(int argc, char * const argv[]);

void ff_run(int (*cb)(void *), void *);

int ff_fcntl(int fd, int cmd, ...);

int ff_sysctl(const int *name, u_int namelen, void *oldp, size_t *oldlenp,
    const void *newp, size_t newlen);

int ff_ioctl(int fd, unsigned long request, ...);

int ff_socket(int domain, int type, int protocol);

int ff_setsockopt(int s, int level, int optname, const void *optval,
    socklen_t optlen);

int ff_getsockopt(int s, int level, int optname, void *optval,
    socklen_t *optlen);

int ff_socketpair(int domain, int type, int protocol, int *sv);

int ff_listen(int s, int backlog);
int ff_bind(int s, const struct linux_sockaddr *addr, socklen_t addrlen);
int ff_accept(int s, struct linux_sockaddr *addr, socklen_t *addrlen);
int ff_connect(int s, const struct linux_sockaddr *name, socklen_t namelen);
int ff_close(int fd);
int ff_shutdown(int s, int how);

int ff_getpeername(int s, struct linux_sockaddr *name,
    socklen_t *namelen);
int ff_getsockname(int s, struct linux_sockaddr *name,
    socklen_t *namelen);

ssize_t ff_read(int d, void *buf, size_t nbytes);
ssize_t ff_readv(int fd, const struct iovec *iov, int iovcnt);

ssize_t ff_write(int fd, const void *buf, size_t nbytes);
ssize_t ff_writev(int fd, const struct iovec *iov, int iovcnt);

ssize_t ff_send(int s, const void *buf, size_t len, int flags);
ssize_t ff_sendto(int s, const void *buf, size_t len, int flags,
    const struct linux_sockaddr *to, socklen_t tolen);
ssize_t ff_sendmsg(int s, const struct msghdr *msg, int flags);

ssize_t ff_recv(int s, void *buf, size_t len, int flags);
ssize_t ff_recvfrom(int s, void *buf, size_t len, int flags,
    struct linux_sockaddr *from, socklen_t *fromlen);
ssize_t ff_recvmsg(int s, struct msghdr *msg, int flags);

void FD_CLR(int fd, fd_set *set);
int  FD_ISSET(int fd, fd_set *set);
void FD_SET(int fd, fd_set *set);
void FD_ZERO(fd_set *set);

int ff_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    struct timeval *timeout);

int ff_poll(struct pollfd fds[], nfds_t nfds, int timeout);

int ff_kqueue(void);
int ff_kevent(int kq, const struct kevent *changelist, int nchanges,
    struct kevent *eventlist, int nevents, const struct timespec *timeout);
int ff_kevent_do_each(int kq, const struct kevent *changelist, int nchanges,
    void *eventlist, int nevents, const struct timespec *timeout,
    void (*do_each)(void **, struct kevent *));

int ff_epoll_create(int size);
int ff_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int ff_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);

int ff_gettimeofday(struct timeval *tv, struct timezone *tz);

int ff_fdisused(int fd);


/* route api begin */
enum FF_ROUTE_CTL {
    FF_ROUTE_ADD,
    FF_ROUTE_DEL,
    FF_ROUTE_CHANGE,
};

enum FF_ROUTE_FLAG {
    FF_RTF_HOST,
    FF_RTF_GATEWAY,
};

/*
 * On success, 0 is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
int ff_route_ctl(enum FF_ROUTE_CTL req, enum FF_ROUTE_FLAG flag,
    struct linux_sockaddr *dst, struct linux_sockaddr *gw,
    struct linux_sockaddr *netmask);

/*
 * This is used in handling ff_msg.
 * The data is a pointer to struct rt_msghdr.
 */
int ff_rtioctl(int fib, void *data, unsigned *plen, unsigned maxlen);


int py_setblocking(int fd, int blocking);

int py_sendmsg(int fd, char* buffers[], int lenarr[], int nbuffers,
               char controlbuf[], int controllen,
               int flags, struct linux_sockaddr *addr, int addrlen);

int py_recvmsg(int fd, char buf[], int bufsize,
               char controlbuf[], int *controllen,
               int *flags, struct linux_sockaddr *addr, int *addrlen);

int py_init_ipv6_addr(unsigned short port, char in6[16], struct sockaddr_in6 *addr);
int py_init_ipv4_addr(unsigned short port, char in4[4], struct sockaddr_in *addr);

int py_parse_ipv6_addr(unsigned short *port, char in6[16],struct sockaddr_in6 *addr);
int py_parse_ipv4_addr(unsigned short *port, char in4[4],struct sockaddr_in *addr);

/* Chat server using livevent */

#include <stdio.h>      // Standard I/O functions (printf, scanf, etc.)
#include <stdlib.h>     // Standard library (exit, malloc, etc.)
#include <string.h>     // String functions (memset, strncpy, strlen, etc.)
#include <unistd.h>     // UNIX standard functions (close, read, write)
#include <netinet/in.h> // Internet address family (sockaddr_in, INADDR_ANY)
#include <arpa/inet.h>  // Internet operations (inet_ntoa for IP conversion)
#include <errno.h>      // Error number definitions
#include <fcntl.h>      // File control options
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>

#define PORT 8080        // Server will listen on port 8080
#define BUFFER_SIZE 1024 // Size of message buffers
#define MAX_NAME_LEN 32  // Maximum length for client usernames

// struct to hold client info for chat server

typedef struct {
    struct bufferevent *bev;
    char name[MAX_NAME_LEN];     // Client's username
} client_t;

// Global state
static struct event_base *base;
static client_t *clients[FD_SETSIZE]; // indexed by fd

static void broadcast_message(int sender_fd, const char* msg) {
    // Create buffer for formatted message (extra space for username and formatting)
    for (int i = 0; i < FD_SETSIZE; i++){
        if (clients[i] && i != sender_fd) {
            bufferevent_write(clients[i]->bev, msg, strlen(msg));
        }
    }
}

static void broadcast_with_name(int sender_fd, const char *text) {
    char out[BUFFER_SIZE + MAX_NAME_LEN + 10];
    snprintf(out, sizeof(out), "[%s]: %s\n", clients[sender_fd]->name, text);
    broadcast_message(sender_fd, out);
}

// Read callback

static void on_read(struct bufferevent *bev, void *ctx) {
    int fd = bufferevent_getfd(bev);
    char buf[BUFFER_SIZE];
    size_t n;

    while ((n = bufferevent_read(bev, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r')) {
            buf[--n] = '\0';
        }
        if (n == 0) return;
        printf("[Server relay] %s (fd %d): %s\n", clients[fd]->name, fd, buf);
        if (strncmp(buf, "/name ", 6) == 0) {
            char old[MAX_NAME_LEN];
            strncpy(old, clients[fd]->name, MAX_NAME_LEN);
            char *newn = buf + 6;
            while (*newn == ' ') newn++;
            if (*newn) {
                strncpy(clients[fd]->name, newn, MAX_NAME_LEN-1);
                clients[fd]->name[MAX_NAME_LEN-1] = '\0';
                char msg[BUFFER_SIZE];
                snprintf(msg, sizeof(msg), "*** %s is now known as %s ***\n", old, clients[fd]->name);
                broadcast_message(-1, msg);
                bufferevent_write(bev, "Name updated\n", 12);
            }
        } else if (strncmp(buf, "/help", 5) == 0) {
            const char *help =
                "Commands:\n"
                "/name <newname> - change your name\n"
                "/help - show this help\n"
                "'^]' is telnet escape (client-side)\n";
            bufferevent_write(bev, help, strlen(help));
        } else {
            broadcast_with_name(fd, buf);
        }        
    }
}

// Event callback (disconnect, errors)
static void on_event(struct bufferevent *bev, short events, void *ctx) {
    int fd = bufferevent_getfd(bev);
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR))  {
        char msg[BUFFER_SIZE];
        snprintf(msg, sizeof(msg), "*** %s left the chat ***\n", clients[fd]->name);
        broadcast_message(-1, msg);

        printf("Client %s (fd %d) disconnected\n", clients[fd]->name, fd);
        bufferevent_free(bev);
        free(clients[fd]);
        clients[fd] = NULL;
    }
}

// Accept callback
static void on_accept(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *addr, int socklen, void *ctx) {
    struct sockaddr_in *sin = (struct sockaddr_in*)addr;
    printf("New connection from %s:%d (fd %d)\n", inet_ntoa(sin->sin_addr), ntohs(sin->sin_port), fd);

    struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);

    client_t *cl = calloc(1, sizeof(client_t));
    cl->bev = bev;
    snprintf(cl->name, MAX_NAME_LEN, "User%d", fd);
    clients[fd] = cl;

    bufferevent_setcb(bev, on_read, NULL, on_event, NULL);
    bufferevent_enable(bev, EV_READ|EV_WRITE);

    char welcome[BUFFER_SIZE];
    snprintf(welcome, sizeof(welcome), "Welcome! Your name is %s\n", cl->name);
    bufferevent_write(bev, welcome, strlen(welcome));

    char joinmsg[BUFFER_SIZE];
    snprintf(joinmsg, sizeof(joinmsg), "*** %s joined the chat ***\n", cl->name);
    broadcast_message(-1, joinmsg);
}

int main() {
    struct sockaddr_in sin;
    base = event_base_new();
    if (!base) {
        fprintf(stderr, "Cloud not init libevent!\n");
        return 1;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(PORT);

    struct evconnlistener *listener = evconnlistener_new_bind(
        base, on_accept, NULL,
        LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
        (struct sockaddr*)&sin, sizeof(sin)
    );
    if(!listener) {
        perror("Could not create listener");
        return 1;
    }

    printf("Chat server running on port %d (libevent)\n", PORT);
    event_base_dispatch(base);

    evconnlistener_free(listener);
    event_base_free(base);
    return 0;
}
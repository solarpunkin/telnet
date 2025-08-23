#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_NAME_LEN 32

// struct to hold client info for chat server

typedef struct {
    int socket;
    char name[MAX_NAME_LEN];
    int active;
} client_t;

// Blocking TCP echo server

void blocking_echo_server() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    int bytes_read;

    printf("Starting blocking TCP echo server on port %d...\n", PORT);
    // Create Socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0))<0){
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options to reuse address

    int opt =1 ;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))<0){
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    // configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr))<0){
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    // listen for connections
    if(listen(server_fd, 5)<0){
        perror("listen failed");
        exit(EXIT_FAILURE);
    }
    printf("Echo server listenting on port %d\n", PORT);

    while(1){
        // accept connections(blocking)
        if ((client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len))<0){
            perror ("accept failed");
            exit(EXIT_FAILURE);
        }
        printf("CLient connected: %s:%d\n",
        inet_ntoa(client_addr.sin_addr),
    ntohs(client_addr.sin_port));

    // Handle client (blocking - server only one client at a time)
    while ((bytes_read = recv(client_fd, buffer, BUFFER_SIZE-1, 0))>0 ){
        buffer[bytes_read] = '\0';
        printf("Received: %s", buffer);
        
        // echo back to client
        if (send(client_fd, buffer, bytes_read, 0)<0){
            perror("send failed");
            break;
        }
    }
    if(bytes_read < 0){
        perror("recv failed");
    }
    printf("Client Disconnected\n");
    close(client_fd);
    }
    close (server_fd);
}

int main (int argc, char *argv[]){
    int choice = 1;
    if (argc>1){
        choice = atoi(argv[1]);
    }
    else {
        printf("Choose server type:\n");
        printf("1. Blocking TCP echo server\n");
        printf("Enter choice [1]: ");
        scanf("%d", &choice);
    }
    switch (choice) {
        case 1:
            blocking_echo_server();
            break;
        default:
        printf("Invalid choice.\n");
        break;
    }
    return 0;
}
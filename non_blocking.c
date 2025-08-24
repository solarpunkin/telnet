// ============================================================================
// NON-BLOCKING I/O ECHO SERVER USING SELECT()
// ============================================================================
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
#define MAX_CLIENTS 10

// struct to hold client info for chat server

typedef struct {
    int socket;
    char name[MAX_NAME_LEN];
    int active;
} client_t;

void nonblocking_echo_server_select(){
    int server_fd, max_fd;
    int client_sockets[MAX_CLIENTS];
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    fd_set read_fds, master_fds;
    int i, bytes_read, new_client;
    
    printf("Starting non-blocking TCP echo server (select) on port %d...\n", PORT);

    //initialize client sockets array
    for(int i=0;i < MAX_CLIENTS; i++) {
        client_sockets[i] = -1;
    }

    // Create socket

    if((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options to reuse address
    int opt = 1;
    if((setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))<0) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }
    // Confiure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind and listen

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 5) < 0){
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Non-blocking echo server listening on port %d\n", PORT);

    // Initialize file descriptor sets
    FD_ZERO(&master_fds);
    FD_SET(server_fd, &master_fds);
    max_fd = server_fd;

    while(1) {
        read_fds = master_fds;

        // Wait for activity on any socket
        if (select(max_fd+1, &read_fds, NULL, NULL, NULL) < 0) {
            perror("select failed");
            break;
        }
        // Check if server socket has activity (new connection)
        if(FD_ISSET(server_fd, &read_fds)) {
            if ((new_client = accept(server_fd, (struct sockaddr*)&client_addr, &client_len)) < 0){
                perror("client failed");
            }
            else {
                // Add new client to array
                for (i = 0; i < MAX_CLIENTS; i++) {
                    if(client_sockets[i] == -1) {
                        client_sockets[i] = new_client;
                        FD_SET(new_client, &master_fds);
                        if (new_client > max_fd) {
                            max_fd = new_client;
                        }
                        printf("New client connected: %s:%d (socket %d)\n", 
                        inet_ntoa(client_addr.sin_addr),
                    ntohs(client_addr.sin_port), new_client);
                    break;
                    }
                }
                if(i == MAX_CLIENTS) {
                    printf("Maximum clients reached. Connection rejected.\n");
                    close(new_client);
                }
            }
        }
        // Check all client sockets for activity
        for (i = 0; i < MAX_CLIENTS; i++) {
            int client_fd = client_sockets[i];

            if(client_fd != 1 && FD_ISSET(client_fd, &read_fds)) {
            bytes_read = recv(client_fd, buffer, BUFFER_SIZE-1, 0);
            
            if (bytes_read <= 0) {
                // Client disconnected or error
                if (bytes_read == 0) {
                    printf("client on socket %d disconnected\n", client_fd);

                }
                else {
                    printf("recv failed");
                }
                close(client_fd);
                FD_CLR(client_fd, &master_fds);
                client_sockets[i] = -1;
            } else {
                // Echo data back
                buffer[bytes_read] = '\0';
                printf("Socket %d: %s", client_fd, buffer);

                if (send(client_fd, buffer, bytes_read, 0) < 0) {
                    perror("send failed");
                    close(client_fd);
                    FD_CLR(client_fd, &master_fds);
                    client_sockets[i] = -1;
                }
            }
        }
    }
}
    
    close(server_fd);
}

int main(int argc, char *argv[]) {
    int choice = 1; // Default to chat server
    
    if (argc > 1) {
        choice = atoi(argv[1]);
    } else {
        // printf("Choose server type:\n");
        // printf("1. Blocking TCP Echo Server\n");
        printf("Non-blocking Echo Server (select)\n");
        // printf("3. Chat Server (default)\n");
        // printf("Enter choice (1-3): ");
        scanf("%d", &choice);
    }
    switch (choice) {
        // case 1:
        //     blocking_echo_server();
        //     break;
        case 1:
            nonblocking_echo_server_select();
            break;
        // case 3:
        //     chat_server();
        //     break;
        default:
            printf("Invalid choice.\n");
            break;
    }
    
    return 0;
}


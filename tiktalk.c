#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>

#define PORT 8080
#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024
#define MAX_NAME_LEN 32

// Structure to hold client information for chat server
typedef struct {
    int socket;
    char name[MAX_NAME_LEN];
    int active;
} client_t;

// ============================================================================
// 1. BLOCKING TCP ECHO SERVER
// ============================================================================
void blocking_echo_server() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    int bytes_read;

    printf("Starting blocking TCP echo server on port %d...\n", PORT);

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options to reuse address
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(server_fd, 5) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Echo server listening on port %d\n", PORT);

    while (1) {
        // Accept connection (blocking)
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept failed");
            continue;
        }

        printf("Client connected: %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), 
               ntohs(client_addr.sin_port));

        // Handle client (blocking - serves one client at a time)
        while ((bytes_read = recv(client_fd, buffer, BUFFER_SIZE - 1, 0)) > 0) {
            buffer[bytes_read] = '\0';
            printf("Received: %s", buffer);
            
            // Echo back to client
            if (send(client_fd, buffer, bytes_read, 0) < 0) {
                perror("send failed");
                break;
            }
        }

        if (bytes_read < 0) {
            perror("recv failed");
        }

        printf("Client disconnected\n");
        close(client_fd);
    }

    close(server_fd);
}

// ============================================================================
// 2. NON-BLOCKING I/O ECHO SERVER USING SELECT()
// ============================================================================
void nonblocking_echo_server_select() {
    int server_fd, max_fd;
    int client_sockets[MAX_CLIENTS];
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    fd_set read_fds, master_fds;
    int i, bytes_read, new_client;

    printf("Starting non-blocking TCP echo server (select) on port %d...\n", PORT);

    // Initialize client sockets array
    for (i = 0; i < MAX_CLIENTS; i++) {
        client_sockets[i] = -1;
    }

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind and listen
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 5) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Non-blocking echo server listening on port %d\n", PORT);

    // Initialize file descriptor sets
    FD_ZERO(&master_fds);
    FD_SET(server_fd, &master_fds);
    max_fd = server_fd;

    while (1) {
        read_fds = master_fds;

        // Wait for activity on any socket
        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) {
            perror("select failed");
            break;
        }

        // Check if server socket has activity (new connection)
        if (FD_ISSET(server_fd, &read_fds)) {
            new_client = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
            if (new_client < 0) {
                perror("accept failed");
            } else {
                // Add new client to array
                for (i = 0; i < MAX_CLIENTS; i++) {
                    if (client_sockets[i] == -1) {
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
                if (i == MAX_CLIENTS) {
                    printf("Maximum clients reached. Connection rejected.\n");
                    close(new_client);
                }
            }
        }

        // Check all client sockets for activity
        for (i = 0; i < MAX_CLIENTS; i++) {
            int client_fd = client_sockets[i];
            
            if (client_fd != -1 && FD_ISSET(client_fd, &read_fds)) {
                bytes_read = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
                
                if (bytes_read <= 0) {
                    // Client disconnected or error
                    if (bytes_read == 0) {
                        printf("Client on socket %d disconnected\n", client_fd);
                    } else {
                        perror("recv failed");
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

// ============================================================================
// 3. SIMPLE CHAT SERVER (Multi-client with messaging)
// ============================================================================
void broadcast_message(client_t clients[], int sender_idx, const char* message) {
    char broadcast_msg[BUFFER_SIZE + MAX_NAME_LEN + 10];
    
    // Format message with sender's name
    if (sender_idx >= 0) {
        snprintf(broadcast_msg, sizeof(broadcast_msg), "[%s]: %s", 
                 clients[sender_idx].name, message);
    } else {
        strncpy(broadcast_msg, message, sizeof(broadcast_msg) - 1);
        broadcast_msg[sizeof(broadcast_msg) - 1] = '\0';
    }
    
    // Send to all active clients except sender
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && i != sender_idx) {
            if (send(clients[i].socket, broadcast_msg, strlen(broadcast_msg), 0) < 0) {
                perror("broadcast send failed");
            }
        }
    }
}

void chat_server() {
    int server_fd, max_fd;
    client_t clients[MAX_CLIENTS];
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    fd_set read_fds, master_fds;
    int i, bytes_read, new_client;

    printf("Starting chat server on port %d...\n", PORT);

    // Initialize clients array
    for (i = 0; i < MAX_CLIENTS; i++) {
        clients[i].socket = -1;
        clients[i].active = 0;
        memset(clients[i].name, 0, MAX_NAME_LEN);
    }

    // Create and configure server socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 5) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Chat server listening on port %d\n", PORT);
    printf("Clients can connect and chat with each other!\n");

    FD_ZERO(&master_fds);
    FD_SET(server_fd, &master_fds);
    max_fd = server_fd;

    while (1) {
        read_fds = master_fds;

        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) {
            perror("select failed");
            break;
        }

        // Handle new connections
        if (FD_ISSET(server_fd, &read_fds)) {
            new_client = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
            if (new_client < 0) {
                perror("accept failed");
            } else {
                // Find empty slot for new client
                for (i = 0; i < MAX_CLIENTS; i++) {
                    if (!clients[i].active) {
                        clients[i].socket = new_client;
                        clients[i].active = 1;
                        snprintf(clients[i].name, MAX_NAME_LEN, "User%d", new_client);
                        
                        FD_SET(new_client, &master_fds);
                        if (new_client > max_fd) {
                            max_fd = new_client;
                        }

                        printf("New client connected: %s:%d (socket %d, name: %s)\n",
                               inet_ntoa(client_addr.sin_addr),
                               ntohs(client_addr.sin_port), 
                               new_client, clients[i].name);

                        // Send welcome message
                        char welcome[BUFFER_SIZE];
                        snprintf(welcome, sizeof(welcome), 
                                "Welcome to the chat server! Your name is %s\n"
                                "Commands: /name <newname> - change your name\n"
                                "Type messages to chat with others!\n", 
                                clients[i].name);
                        send(new_client, welcome, strlen(welcome), 0);

                        // Notify other clients
                        char join_msg[BUFFER_SIZE];
                        snprintf(join_msg, sizeof(join_msg), "*** %s joined the chat ***\n", 
                                clients[i].name);
                        broadcast_message(clients, -1, join_msg);
                        break;
                    }
                }
                if (i == MAX_CLIENTS) {
                    printf("Maximum clients reached. Connection rejected.\n");
                    close(new_client);
                }
            }
        }

        // Handle client messages
        for (i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].active && FD_ISSET(clients[i].socket, &read_fds)) {
                bytes_read = recv(clients[i].socket, buffer, BUFFER_SIZE - 1, 0);
                
                if (bytes_read <= 0) {
                    // Client disconnected
                    printf("Client %s (socket %d) disconnected\n", 
                           clients[i].name, clients[i].socket);
                    
                    // Notify other clients
                    char leave_msg[BUFFER_SIZE];
                    snprintf(leave_msg, sizeof(leave_msg), "*** %s left the chat ***\n", 
                            clients[i].name);
                    broadcast_message(clients, -1, leave_msg);
                    
                    close(clients[i].socket);
                    FD_CLR(clients[i].socket, &master_fds);
                    clients[i].active = 0;
                } else {
                    buffer[bytes_read] = '\0';
                    
                    // Remove newline if present
                    if (buffer[bytes_read - 1] == '\n') {
                        buffer[bytes_read - 1] = '\0';
                    }
                    
                    printf("Message from %s: %s\n", clients[i].name, buffer);
                    
                    // Handle commands
                    if (strncmp(buffer, "/name ", 6) == 0) {
                        char old_name[MAX_NAME_LEN];
                        strncpy(old_name, clients[i].name, MAX_NAME_LEN);
                        
                        strncpy(clients[i].name, buffer + 6, MAX_NAME_LEN - 1);
                        clients[i].name[MAX_NAME_LEN - 1] = '\0';
                        
                        char name_change_msg[BUFFER_SIZE];
                        snprintf(name_change_msg, sizeof(name_change_msg), 
                                "*** %s is now known as %s ***\n", 
                                old_name, clients[i].name);
                        broadcast_message(clients, -1, name_change_msg);
                        
                        snprintf(name_change_msg, sizeof(name_change_msg), 
                                "Your name has been changed to: %s\n", clients[i].name);
                        send(clients[i].socket, name_change_msg, strlen(name_change_msg), 0);
                    } else {
                        // Broadcast regular message to all other clients
                        broadcast_message(clients, i, buffer);
                    }
                }
            }
        }
    }

    // Cleanup
    for (i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active) {
            close(clients[i].socket);
        }
    }
    close(server_fd);
}

// ============================================================================
// MAIN FUNCTION - Choose which server to run
// ============================================================================
int main(int argc, char *argv[]) {
    int choice = 3; // Default to chat server
    
    if (argc > 1) {
        choice = atoi(argv[1]);
    } else {
        printf("Choose server type:\n");
        printf("1. Blocking TCP Echo Server\n");
        printf("2. Non-blocking Echo Server (select)\n");
        printf("3. Chat Server (default)\n");
        printf("Enter choice (1-3): ");
        scanf("%d", &choice);
    }
    
    switch (choice) {
        case 1:
            blocking_echo_server();
            break;
        case 2:
            nonblocking_echo_server_select();
            break;
        case 3:
            chat_server();
            break;
        default:
            printf("Invalid choice. Running chat server.\n");
            chat_server();
            break;
    }
    
    return 0;
}
// ============================================================================
// SIMPLE CHAT SERVER (Multi-client with messaging)
// ============================================================================
#include <stdio.h>      // Standard I/O functions (printf, scanf, etc.)
#include <stdlib.h>     // Standard library (exit, malloc, etc.)
#include <string.h>     // String functions (memset, strncpy, strlen, etc.)
#include <unistd.h>     // UNIX standard functions (close, read, write)
#include <sys/socket.h> // Socket functions (socket, bind, listen, accept, send, recv)
#include <sys/select.h> // select() function for I/O multiplexing
#include <netinet/in.h> // Internet address family (sockaddr_in, INADDR_ANY)
#include <arpa/inet.h>  // Internet operations (inet_ntoa for IP conversion)
#include <errno.h>      // Error number definitions
#include <fcntl.h>      // File control options

#define PORT 8080        // Server will listen on port 8080
#define MAX_CLIENTS 10   // Maximum number of simultaneous clients
#define BUFFER_SIZE 1024 // Size of message buffers
#define MAX_NAME_LEN 32  // Maximum length for client usernames

// struct to hold client info for chat server

typedef struct {
    int socket;                  // FD for client socket
    char name[MAX_NAME_LEN];     // Client's username
    int active;                  // 1 : connected, 0 : disconnected
} client_t;

void broadcast_message(client_t clients[], int sender_idx, const char* message) {
    // Create buffer for formatted message (extra space for username and formatting)
    char broadcast_msg[BUFFER_SIZE + MAX_NAME_LEN + 10];
    int msg_len;        // actual message length

    // Format message with sender's name as [Username]: message\n
    if (sender_idx >= 0) {
        msg_len = snprintf(broadcast_msg, sizeof(broadcast_msg), "[%s]: %s\n",
        clients[sender_idx].name, message);
    }
    else {
        // System message (join/leave notifications)
        msg_len = snprintf(broadcast_msg, sizeof(broadcast_msg), "%s", message);
    }

    // Buffer sanity check (if message is too long, truncate it and null-terminate)
    if (msg_len >= sizeof(broadcast_msg)) {
        msg_len = sizeof(broadcast_msg) - 1;
        broadcast_msg[msg_len] = '\0';
    }

    printf("Broadcasting: %s", broadcast_msg); // Debug output

    // Send to all active clients except sender
    // Use send() system call to transmit data over socket
    for (int i = 0; i < MAX_CLIENTS; i++) {             // Loop through all clients
        if (clients[i].active && i != sender_idx) {     // Send message only to active clients who aren't the sender
            if (send(clients[i].socket, broadcast_msg, msg_len, 0) < 0) {
                perror("broadcast send failed");
                printf("Failed to send to client %s (socket %d)\n", clients[i].name, clients[i].socket);
            }
        }
    }
}

void chat_server() {
    int server_fd, max_fd;              // FD for server and highest FD
    client_t clients[MAX_CLIENTS];      // Array to store all client info
    struct sockaddr_in server_addr, client_addr;        // Socket address structures
    socklen_t client_len = sizeof(client_addr);         // Size of client address structure
    char buffer[BUFFER_SIZE];                           // Buffer for receiving messages
    fd_set read_fds, master_fds;                        // FD sets for select()
    int i, bytes_read, new_client;

    printf("Starting chat server on port %d...\n", PORT);

    // Initialize clients array
    for (i = 0; i < MAX_CLIENTS; i++) {
        clients[i].socket = -1;                         // -1 indicates unused slot
        clients[i].active = 0;                          // mark as inactive
        memset(clients[i].name, 0, MAX_NAME_LEN);       // clear name buffer 
    }

    // Create and configure TCP server socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));     // Allow reusing the address 
                                                                            // immediately after server restart
                                                                            // Prevents "Address already in use" error
    // Configure Server address
    memset(&server_addr, 0, sizeof(server_addr));   
    server_addr.sin_family = AF_INET;               // IPv4
    server_addr.sin_addr.s_addr = INADDR_ANY;       // Accept connections from any IP
    server_addr.sin_port = htons(PORT);             // Convert port from host to network byte order

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 5) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Chat server listening on port %d\n", PORT);
    printf("Clients can connet and chat with each other!\n");
    
    // Initialize File Descriptor Sets
    FD_ZERO(&master_fds);              // Clear the master set
    FD_SET(server_fd, &master_fds);    // Add server socket to master set
    max_fd = server_fd;                // Track highest file descriptor number

    while(1) {
        read_fds = master_fds;          // Copy master set (select() modifies the set)

        if (select(max_fd+1, &read_fds, NULL, NULL, NULL) < 0 ) {
            perror("select failed");
            break;
        }
        /* 
        select(): Monitor multiple file descriptors for activity
        max_fd + 1: Number of file descriptors to monitor
        &read_fds: Set of file descriptors to check for reading
        NULL, NULL, NULL: We're not monitoring write, exception, or timeout
        Returns when at least one file descriptor has data ready to read
        */


        // HANDLE new connections
        if (FD_ISSET(server_fd, &read_fds)) {       // FD_ISSET: Checks if server socket has activity
            new_client = accept (server_fd, (struct sockaddr*)&client_addr, &client_len);
            if (new_client < 0) {
                perror("accept failed");
            }
            else {
                // Find empty slot for new client
                for (i = 0; i < MAX_CLIENTS; i++) {
                    if(!clients[i].active) {                // Find empty slot
                        clients[i].socket = new_client;     // Store client socket
                        clients[i].active = 1;              // Mark as active
                        snprintf(clients[i].name, MAX_NAME_LEN, "User%d", new_client);  // Assign default username based on socket number

                        // Add new client socket to the set that select() monitors
                        // Update max_fd if this is the highest numbered file descriptor
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
                    broadcast_message(clients, -1, join_msg);       // broadcast_message() with -1 means it's a system message
                    break;
                    }
                }
                if (i == MAX_CLIENTS) {
                    printf("Maximum clients reached. Connection rejected.\n");
                    close(new_client);
                }
            }
        }

        // Handle new clients

        for (i = 0; i < MAX_CLIENTS; i++)           
        {
            if (clients[i].active && FD_ISSET(clients[i].socket, &read_fds)) {    // Check if client is active AND has data ready to read
                // Clear buffer before reading to prevent corruption
                memset(buffer, 0, BUFFER_SIZE);     
                bytes_read = recv(clients[i].socket, buffer, BUFFER_SIZE - 1, 0);
                // BUFFER_SIZE - 1 : Leave space for null terminator
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
                }
                else {
                    /*Process Client Messages*/
                    
                    // Ensure null termination
                    buffer[bytes_read] = '\0';

                    // Remove trailing newlines and carriage functions
                    while (bytes_read > 0 &&
                    (buffer[bytes_read - 1] == '\n' || buffer[bytes_read - 1] == '\r')) {
                        buffer[bytes_read - 1] = '\0';
                        bytes_read--;
                    }
                    // Skip empty messages
                    if (strlen(buffer) == 0) {
                        continue;
                    }

                    printf("Message from %s (socket %d): '%s'\n", clients[i].name, clients[i].socket, buffer);

                    // Handle commands
                    if (strncmp(buffer, " /name ", 6) == 0) {        
                        char old_name[MAX_NAME_LEN];    
                        strncpy(old_name, clients[i].name, MAX_NAME_LEN - 1);
                        old_name[MAX_NAME_LEN - 1] = '\0';

                        // Extract new name (skip "/name ")
                        char *new_name = buffer + 6;
                        // Remove any leading/trailing spaces
                        while (*new_name == ' ') new_name++;
                        if (strlen(new_name) > 0) {
                            strncpy(clients[i].name, new_name, MAX_NAME_LEN - 1);
                            clients[i].name[MAX_NAME_LEN - 1] = '\0';       // Ensure null termination

                            char name_change_msg[BUFFER_SIZE];
                            snprintf(name_change_msg, sizeof(name_change_msg),
                        "*** %s is now known as %s ***\n",
                    old_name, clients[i].name);                             // Copy new name to client structure with bounds checking
                    
                    broadcast_message(clients, -1, name_change_msg);

                    snprintf(name_change_msg, sizeof(name_change_msg),
                "Your name has been changed to: %s\n", clients[i].name);
                send(clients[i].socket, name_change_msg, strlen(name_change_msg), 0);
                        }
                        else {
                            char error_msg[] = "Error: Name cannot be empty\n";
                            send(clients[i].socket, error_msg, strlen(error_msg), 0);

                        }

                    }
                    else if (strncpy(buffer, "/help", 5) == 0){
                        char help_msg[] = "Available commands:\n"
                                         "/name <newname> - Change your name\n"
                                         "/help - Show this help message\n"
                                         "-----------------------------\n"
                                         "'^]' - Telnet commands:\n"
                                         "'close' - Close the connection\n"
                                         "'exit' - To exit\n"
                                         "'help' - to see telnet commands\n"
                                         "-----------------------------\n"
                                         "Just type to chat with others!\n";
                        send(clients[i].socket, help_msg, strlen(help_msg), 0);
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

int main(int argc, char *argv[]) {
    int choice = 1; // Default to chat server
    
    if (argc > 1) {
        choice = atoi(argv[1]);
    } else {
        printf("Chat Server\n");
        scanf("%d", &choice);
    }
    switch (choice) {
        case 1:
            chat_server();
            break;
        default:
            printf("Invalid choice.\n");
            break;
    }
    
    return 0;
}

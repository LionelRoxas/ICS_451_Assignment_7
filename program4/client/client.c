/**
 * TCP Client with 3-way handshake simulation
 * 
 * This client connects to a server, performs a simulated 3-way handshake
 * by sending raw TCP headers, and then proceeds with HTTP communication.
 * Output is logged to both console and output_client.txt file.
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <arpa/inet.h>
 #include <sys/socket.h>
 #include <netinet/in.h>
 #include <time.h>
 
 #define HEADER_SIZE 20  // TCP header size in bytes
 #define FLAG_SYN 0x02
 #define FLAG_ACK 0x10
 #define FLAG_SYNACK 0x12
 #define WINDOW_SIZE 17520
 
 // Structure to represent a TCP header
 typedef struct {
     uint16_t source_port;
     uint16_t dest_port;
     uint32_t seq_num;
     uint32_t ack_num;
     uint8_t data_offset;  // 4 bits data offset, 4 bits reserved
     uint8_t flags;
     uint16_t window_size;
     uint16_t checksum;
     uint16_t urgent_ptr;
 } tcp_header_t;
 
 // File pointer for output
 FILE *output_file = NULL;
 
 // Function to print raw header bytes to both console and file
 void print_raw_header(unsigned char *header, int size) {
     printf("Raw TCP Header: ");
     fprintf(output_file, "Raw TCP Header: ");
     
     for (int i = 0; i < size; i++) {
         printf("%02X ", header[i]);
         fprintf(output_file, "%02X ", header[i]);
     }
     
     printf("\n");
     fprintf(output_file, "\n");
 }
 
 // Function to print TCP header details to both console and file
 void print_tcp_header(tcp_header_t *header) {
     printf("Source port: %d\n", ntohs(header->source_port));
     fprintf(output_file, "Source port: %d\n", ntohs(header->source_port));
     
     printf("Destination port: %d\n", ntohs(header->dest_port));
     fprintf(output_file, "Destination port: %d\n", ntohs(header->dest_port));
     
     printf("Sequence number: %u\n", ntohl(header->seq_num));
     fprintf(output_file, "Sequence number: %u\n", ntohl(header->seq_num));
     
     printf("Acknowledgment number: %u\n", ntohl(header->ack_num));
     fprintf(output_file, "Acknowledgment number: %u\n", ntohl(header->ack_num));
     
     printf("Flags: ");
     fprintf(output_file, "Flags: ");
     
     if (header->flags & FLAG_SYN) {
         printf("SYN ");
         fprintf(output_file, "SYN ");
     }
     if (header->flags & FLAG_ACK) {
         printf("ACK ");
         fprintf(output_file, "ACK ");
     }
     
     printf("\n");
     fprintf(output_file, "\n");
 }
 
 // Function to create and populate a TCP header
 void create_tcp_header(tcp_header_t *header, int src_port, int dst_port, uint32_t seq_num, uint32_t ack_num, uint8_t flags) {
     header->source_port = htons(src_port);
     header->dest_port = htons(dst_port);
     header->seq_num = htonl(seq_num);
     header->ack_num = htonl(ack_num);
     header->data_offset = 0x50;  // 5 words (20 bytes), no options
     header->flags = flags;
     header->window_size = htons(WINDOW_SIZE);
     header->checksum = htons(0xFFFF);  // Dummy checksum
     header->urgent_ptr = 0;
 }
 
 // Function to serialize a TCP header into a byte array
 void serialize_tcp_header(tcp_header_t *header, unsigned char *buffer) {
     memcpy(buffer, &header->source_port, 2);
     memcpy(buffer + 2, &header->dest_port, 2);
     memcpy(buffer + 4, &header->seq_num, 4);
     memcpy(buffer + 8, &header->ack_num, 4);
     buffer[12] = header->data_offset;
     buffer[13] = header->flags;
     memcpy(buffer + 14, &header->window_size, 2);
     memcpy(buffer + 16, &header->checksum, 2);
     memcpy(buffer + 18, &header->urgent_ptr, 2);
 }
 
 // Function to deserialize a byte array into a TCP header
 void deserialize_tcp_header(unsigned char *buffer, tcp_header_t *header) {
     memcpy(&header->source_port, buffer, 2);
     memcpy(&header->dest_port, buffer + 2, 2);
     memcpy(&header->seq_num, buffer + 4, 4);
     memcpy(&header->ack_num, buffer + 8, 4);
     header->data_offset = buffer[12];
     header->flags = buffer[13];
     memcpy(&header->window_size, buffer + 14, 2);
     memcpy(&header->checksum, buffer + 16, 2);
     memcpy(&header->urgent_ptr, buffer + 18, 2);
 }
 
 int main(int argc, char *argv[]) {
     if (argc != 2) {
         fprintf(stderr, "Usage: %s <port>\n", argv[0]);
         return 1;
     }
 
     // Open output file
     output_file = fopen("output_client.txt", "w");
     if (output_file == NULL) {
         perror("Failed to open output file");
         return 1;
     }
 
     int port = atoi(argv[1]);
     int client_socket;
     struct sockaddr_in server_addr;
     unsigned char header_buffer[HEADER_SIZE];
     tcp_header_t header;
     uint32_t client_seq_num, server_seq_num;
     
     // Generate a random Initial Sequence Number (ISN)
     srand(time(NULL));
     client_seq_num = rand();
     
     // Create socket
     client_socket = socket(AF_INET, SOCK_STREAM, 0);
     if (client_socket < 0) {
         perror("Socket creation failed");
         exit(EXIT_FAILURE);
     }
     
     // Set up server address
     memset(&server_addr, 0, sizeof(server_addr));
     server_addr.sin_family = AF_INET;
     server_addr.sin_port = htons(port);
     server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
     
     // Connect to server
     if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
         perror("Connection failed");
         exit(EXIT_FAILURE);
     }
     
     printf("Connected to server on port %d\n", port);
     fprintf(output_file, "Connected to server on port %d\n", port);
     
     // Get client's port number
     struct sockaddr_in local_addr;
     socklen_t addr_len = sizeof(local_addr);
     getsockname(client_socket, (struct sockaddr *)&local_addr, &addr_len);
     int src_port = ntohs(local_addr.sin_port);
     
     printf("Client using source port: %d\n", src_port);
     fprintf(output_file, "Client using source port: %d\n", src_port);
     
     // Step 1: Send SYN
     printf("\n--- Step 1: Client sends SYN ---\n");
     fprintf(output_file, "\n--- Step 1: Client sends SYN ---\n");
     create_tcp_header(&header, src_port, port, client_seq_num, 0, FLAG_SYN);
     serialize_tcp_header(&header, header_buffer);
     print_raw_header(header_buffer, HEADER_SIZE);
     print_tcp_header(&header);
     
     send(client_socket, header_buffer, HEADER_SIZE, 0);
     
     // Step 2: Receive SYN-ACK
     printf("\n--- Step 2: Client receives SYN-ACK ---\n");
     fprintf(output_file, "\n--- Step 2: Client receives SYN-ACK ---\n");
     recv(client_socket, header_buffer, HEADER_SIZE, 0);
     deserialize_tcp_header(header_buffer, &header);
     print_raw_header(header_buffer, HEADER_SIZE);
     print_tcp_header(&header);
     
     // Extract server sequence number and calculate acknowledgment
     server_seq_num = ntohl(header.seq_num);
     
     // Step 3: Send ACK
     printf("\n--- Step 3: Client sends ACK ---\n");
     fprintf(output_file, "\n--- Step 3: Client sends ACK ---\n");
     create_tcp_header(&header, src_port, port, client_seq_num + 1, server_seq_num + 1, FLAG_ACK);
     serialize_tcp_header(&header, header_buffer);
     print_raw_header(header_buffer, HEADER_SIZE);
     print_tcp_header(&header);
     
     send(client_socket, header_buffer, HEADER_SIZE, 0);
     
     printf("\n3-way handshake completed successfully!\n");
     fprintf(output_file, "\n3-way handshake completed successfully!\n");
     
     // Now we can proceed with HTTP communication
     // For this assignment, we'll just close the connection
     close(client_socket);
     
     // Close the output file
     fclose(output_file);
     
     return 0;
 }
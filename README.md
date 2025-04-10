# TCP 3-Way Handshake Simulation

This project implements a simulation of the TCP 3-way handshake protocol using raw TCP headers. The implementation includes both client and server components that communicate with each other to establish a connection using the standard SYN, SYN-ACK, ACK sequence.

## Project Structure

- `client.c` - Client implementation that initiates the handshake
- `server.c` - Server implementation that responds to client requests
- `client_makefile` - Makefile for compiling the client
- `server_makefile` - Makefile for compiling the server
- `output_client.txt` - Sample output from the client
- `output_server.txt` - Sample output from the server
- `status.txt` - Current status of the implementation

## Features

- Raw TCP header creation with all required fields
- Random sequence number generation
- Proper handling of acknowledgment numbers
- Display of both raw header bytes and human-readable header fields
- Command-line port number specification
- Output logging to both console and text files

## TCP Header Implementation

The implementation includes a 20-byte TCP header with the following fields:
- Source port (16 bits)
- Destination port (16 bits)
- Sequence number (32 bits)
- Acknowledgment number (32 bits)
- Data offset and reserved bits (8 bits)
- Control flags (8 bits)
- Window size (16 bits) - Set to 17520 bytes
- Checksum (16 bits) - Set to 0xFFFF
- Urgent pointer (16 bits) - Set to 0

## Building and Running

### Compiling

If you have `make` installed:
```bash
make -f client_makefile
make -f server_makefile
```

If you don't have `make` installed, use these direct commands:
```bash
gcc -Wall -Wextra -std=c99 -o server server.c
gcc -Wall -Wextra -std=c99 -o client client.c
```

### Running

1. First, start the server in one terminal:
```bash
./server 8080
```

2. Then, run the client in a separate terminal:
```bash
./client 8080
```

Replace `8080` with any port number you want to use.

## Output

The programs will display the handshake process in real-time and save the output to `output_client.txt` and `output_server.txt`. The output includes:

- Connection details
- Raw TCP header bytes in hexadecimal format
- Parsed TCP header fields (ports, sequence numbers, flags)
- Step-by-step indication of the handshake progress

## Requirements

- Linux or macOS environment (tested on Linux)
- GCC compiler
- Standard C libraries
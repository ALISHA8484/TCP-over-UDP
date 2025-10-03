# TCP over UDP Implementation

This project is a Python-based implementation of a reliable transport protocol that simulates the core functionalities of TCP (Transmission Control Protocol) using the unreliable UDP (User Datagram Protocol) as its underlying transport layer. It was developed as a final project for a 4th-semester Computer Networks course.

The goal is to demonstrate a deep understanding of TCP's mechanisms by building them from scratch, including connection establishment, reliable data transfer, and connection termination.

---

## Features Implemented 📜

This library successfully implements a wide range of TCP features, from basic connection management to advanced congestion control algorithms.

### Core Functionality
- **Connection Management**:
  - [x] **3-Way Handshake**: Secure connection establishment (`SYN`, `SYN-ACK`, `ACK`).
  - [x] **4-Way Handshake**: Graceful connection termination (`FIN`, `ACK`, `FIN`, `ACK`).
  - [x] **Connection Reset**: Support for `RST` packets to handle invalid states or abnormal termination.
- **Reliable Data Transfer**:
  - [x] **Sequencing and Acknowledgments**: Byte-based sequence and acknowledgment numbers for ordered, gap-free data delivery.
  - [x] **Data Segmentation**: Large data streams are automatically segmented into Maximum Segment Size (MSS) chunks.
  - [x] **Cumulative ACKs**: The receiver can acknowledge multiple segments with a single ACK, improving efficiency.
  - [x] **Out-of-Order Data Buffering**: Packets that arrive out of order are buffered and reassembled correctly.
- **Multi-Client Server**:
  - [x] A fully concurrent server capable of handling multiple client connections simultaneously using a multi-threaded architecture.

### Advanced Features
- **Retransmission Timers**:
  - [x] **Retransmission Timeout (RTO)**: Packets are re-sent if an acknowledgment is not received within a calculated timeout period.
  - [x] **Dynamic RTO Calculation**: The RTO is dynamically adjusted based on network latency using a simplified version of the **Jacobson/Karels algorithm** (calculating `EstimatedRTT` and `DevRTT`).
- **Congestion Control (TCP Reno Style)**:
  - [x] **Congestion Window (`cwnd`)**: Manages the amount of data in flight to avoid overwhelming the network.
  - [x] **Timeout-based Retransmission**: On a timeout, `cwnd` is reset to 1 MSS (acting like Slow Start).
  - [x] **Fast Retransmit**: After receiving 3 duplicate ACKs, the missing segment is retransmitted immediately without waiting for a timeout.
  - [x] **Fast Recovery**: Upon Fast Retransmit, `cwnd` is halved instead of being reset to 1 MSS.
- **Flow Control**:
  - [x] **Sliding Window Protocol**: Both sender and receiver maintain windows to manage data flow.
  - [x] **Receiver Window (`rwnd`)**: The receiver advertises its available buffer space in every ACK, ensuring the sender does not overwhelm it.
  - [x] **Effective Send Window**: The sender's window is constrained by `min(cwnd, rwnd)`.
- **Data Security**:
  - [x] **Simple Data Obfuscation**: The payload of each packet is XOR-ed with a secret key, so data sent over the network is not in plaintext.

---

## Project Structure 📁

The project is organized into three main Python files:

- **`my_tcp_lib.py`**: The core library containing the protocol logic.
  - `Packet`: A class for creating, parsing, and managing packet headers and payloads.
  - `Connection`: Manages the state and logic for a single, established connection (e.g., send/receive buffers, window management, timers). Each connection runs its own threads for sending and receiving data.
  - `TCPSocket`: A wrapper class that mimics the standard Python socket API (`bind`, `listen`, `accept`, `connect`, `close`). It includes the main server listening thread that demultiplexes incoming packets to their respective `Connection` objects.

- **`Server.py`**: A sample server application that uses the `TCPSocket` library to listen for connections, receive data, and send a response.

- **`Client.py`**: A sample client application that connects to the server, sends a large stream of data to test reliability and segmentation, and then gracefully closes the connection.

---

## How to Run 🚀

You can run the client and server applications from your terminal.

1.  **Start the Server**:
    Open a terminal and run the server script. It will bind to `127.0.0.1:12345` and wait for incoming connections.
    ```bash
    python Server.py
    ```

2.  **Run the Client**:
    Open a second terminal and run the client script. It will connect to the server, transfer data, and then close.
    ```bash
    python Client.py
    ```

3.  **Observe the Logs**:
    Both the client and server will print detailed, timestamped logs to the console, showing the protocol's state transitions, packet exchanges, and window adjustments in real-time. This is the best way to see the implemented features in action!

---

## Custom Packet Format 📦

All communication uses a custom packet structure with a header that is packed and unpacked using Python's `struct` module.

The header contains the following fields:
- **Source Port** (16 bits)
- **Destination Port** (16 bits)
- **Sequence Number** (32 bits)
- **Acknowledgment Number** (32 bits)
- **Flags** (8 bits for `SYN`, `ACK`, `FIN`, `RST`)
- **Window Size** (16 bits, for flow control)
- **Payload Length** (16 bits)
- **Payload** (variable length, up to MSS)
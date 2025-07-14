import threading
import socket # For UDP socket operation
import time
import queue # For accept queue
from Packet import Packet, log_event , MSS # Importing Packet and log_event from the Packet module
import Connection # Importing Connection class for managing individual connections
# --- Socket Class ---
class TCPSocket:
    """
    Simulates a TCP socket using UDP.
    Handles binding, listening, accepting connections, and managing multiple connections.
    """
    def __init__(self):
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.setblocking(False) # Non-blocking for receive loop
        self.is_listening = False
        self.accept_queue = queue.Queue() # For established connections waiting to be accepted
        self.active_connections = {} # {remote_addr: Connection_object}
        
        self.listening_thread = None
        self._running = False

    def bind(self, address):
        """
        Binds the UDP socket to a specific address (IP, Port).
        Mandatory for server, optional for client.
        """
        self.udp_socket.bind(address)
        log_event(f"Socket bound to {address}")

    def listen(self, backlog):
        """
        Puts the server socket into listening mode.
        'backlog' defines the maximum length of the queue of pending connections.
        """
        self.is_listening = True
        self.max_backlog = backlog
        log_event(f"Socket listening with backlog {backlog}")
        self._running = True
        self.listening_thread = threading.Thread(target=self._listen_loop)
        self.listening_thread.daemon = True
        self.listening_thread.start()
        log_event(f"Listening thread started on {self.udp_socket.getsockname()}")

    def _listen_loop(self):
        """
        Continuously receives UDP packets and dispatches them to appropriate connections
        or handles new connection requests (SYN).
        """
        while self._running:
            try:
                data, addr = self.udp_socket.recvfrom(MSS + Packet.HEADER_FORMAT_ACTUAL.__sizeof__()) # Max packet size is MSS + header
                packet = Packet.from_bytes(data)
                log_event(f"Received UDP packet from {addr}: {packet}")

                if addr in self.active_connections:
                    # Packet for an active connection
                    self.active_connections[addr].handle_incoming_packet(packet)
                elif packet.is_syn():
                    # New connection attempt (SYN)
                    if self.is_listening and self.accept_queue.qsize() < self.max_backlog: # Check backlog
                        log_event(f"Received SYN from {addr}. Initiating 3-way handshake.")
                        # Handle SYN, send SYN-ACK [cite: 45]
                        new_conn = Connection(self.udp_socket, addr, is_server=True)
                        new_conn.state = "SYN_RCVD"
                        new_conn.peer_seq_num = packet.seq_num # Store peer's initial sequence number
                        new_conn.next_expected_seq = packet.seq_num + 1 # Next expected from peer is their ISN + 1

                        syn_ack_packet = Packet(self.udp_socket.getsockname()[1], addr[1],
                                                new_conn.my_seq_num, new_conn.next_expected_seq,
                                                Packet.SYN | Packet.ACK, new_conn.receive_window_size)
                        self.udp_socket.sendto(syn_ack_packet.to_bytes(), addr)
                        log_event(f"Sent SYN-ACK to {addr}. Seq={syn_ack_packet.seq_num}, Ack={syn_ack_packet.ack_num}")
                        
                        # Store half-open connection (simplified, a real TCP stack has a SYN queue)
                        # Here, we store the connection object. It needs to be moved to active_connections upon ACK.
                        self.active_connections[addr] = new_conn # Temporarily add to active connections for ACK handling

                    else:
                        log_event(f"SYN from {addr} rejected: not listening or backlog full.")
                        # Optionally send RST
                        rst_packet = Packet(self.udp_socket.getsockname()[1], addr[1], 0, 0, Packet.RST)
                        self.udp_socket.sendto(rst_packet.to_bytes(), addr)

                elif addr in self.active_connections and self.active_connections[addr].state == "SYN_RCVD" and packet.is_ack() and \
                     packet.ack_num == self.active_connections[addr].my_seq_num + 1 and packet.seq_num == self.active_connections[addr].peer_seq_num + 1:
                    # Final ACK of 3-way handshake from client
                    log_event(f"Received final ACK from {addr}. Connection ESTABLISHED.")
                    conn = self.active_connections[addr]
                    conn.state = "ESTABLISHED"
                    conn._start_connection_threads() # Start connection-specific threads
                    self.accept_queue.put((conn, addr)) # Add to accept queue

                else:
                    # Unrecognized packet or invalid flags
                    log_event(f"Received unrecognized/invalid packet from {addr}: {packet}. Sending RST.")
                    rst_packet = Packet(self.udp_socket.getsockname()[1], addr[1], 0, 0, Packet.RST)
                    self.udp_socket.sendto(rst_packet.to_bytes(), addr)

            except socket.error as e:
                if e.errno == 10035: # WSAEWOULDBLOCK (non-blocking socket has no data)
                    pass
                else:
                    log_event(f"Socket error in listen loop: {e}")
            except ValueError as e:
                log_event(f"Packet parsing error: {e}")
            except Exception as e:
                log_event(f"Unexpected error in listen loop: {e}")
            time.sleep(0.01) # Small delay to prevent busy-waiting

    def accept(self):
        """
        Blocks until a new connection is established and returns the connection object and remote address.
        """
        log_event("Waiting for incoming connection (blocking on accept).")
        conn, addr = self.accept_queue.get() # Blocks until an item is available
        log_event(f"Accepted connection from {addr}.")
        return conn, addr

    def connect(self, remote_address):
        """
        Initiates a 3-way handshake to connect to a remote server.
        Returns a Connection object upon successful establishment.
        """
        log_event(f"Attempting to connect to {remote_address}...")
        self.remote_address = remote_address
        conn = Connection(self.udp_socket, remote_address)
        self.active_connections[remote_address] = conn # Add to active connections

        # Step 1: Send SYN
        syn_packet = Packet(self.udp_socket.getsockname()[1], remote_address[1],
                            conn.my_seq_num, conn.next_expected_seq, Packet.SYN)
        
        conn.state = "SYN_SENT"
        retries = 3 # Number of retries for handshake
        timeout = 1
        
        for i in range(retries):
            try:
                self.udp_socket.sendto(syn_packet.to_bytes(), remote_address)
                log_event(f"Sent SYN to {remote_address} (Attempt {i+1}). Seq={syn_packet.seq_num}")

                start_time = time.time()
                while time.time() - start_time < timeout:
                    # In a non-blocking setup, you'd need to poll or have a dedicated receive for this.
                    # For simplicity, we'll try to get it from the main receive loop's demux.
                    # A better way would be a specific handler for SYN-ACK replies.
                    # This is where a small temporary buffer for packets awaiting handshake response would be useful.
                    # For now, rely on handle_incoming_packet from the main listener eventually processing it.
                    # A dedicated mechanism for client-side handshake receive is needed.
                    
                    # For now, we assume the server side of _listen_loop in server/client model or a simplified poll.
                    # A more direct client-side receive for handshake:
                    self.udp_socket.setblocking(True) # Temporarily blocking for handshake receive
                    self.udp_socket.settimeout(timeout) # Set timeout for blocking receive
                    try:
                        data, addr = self.udp_socket.recvfrom(MSS + Packet.HEADER_FORMAT_ACTUAL.__sizeof__())
                        if addr == remote_address:
                            resp_packet = Packet.from_bytes(data)
                            if resp_packet.is_syn() and resp_packet.is_ack() and resp_packet.ack_num == conn.my_seq_num + 1:
                                # Step 2: Received SYN-ACK
                                log_event(f"Received SYN-ACK from {remote_address}. Seq={resp_packet.seq_num}, Ack={resp_packet.ack_num}")
                                conn.peer_seq_num = resp_packet.seq_num
                                conn.next_expected_seq = resp_packet.seq_num + 1
                                conn.my_seq_num += 1 # Advance our sequence number because SYN consumes 1 byte
                                conn.state = "ESTABLISHED" # Client becomes ESTABLISHED after receiving SYN-ACK and sending ACK

                                # Step 3: Send final ACK
                                ack_packet = Packet(self.udp_socket.getsockname()[1], remote_address[1],
                                                    conn.my_seq_num, conn.next_expected_seq, Packet.ACK)
                                self.udp_socket.sendto(ack_packet.to_bytes(), remote_address)
                                log_event(f"Sent final ACK to {remote_address}.") # [cite: 1]
                                
                                conn._start_connection_threads() # Start connection-specific threads
                                self.udp_socket.setblocking(False) # Revert to non-blocking
                                return conn # Connection established
                    except socket.timeout:
                        log_event(f"Timeout waiting for SYN-ACK from {remote_address}.")
                    except Exception as e:
                        log_event(f"Error during SYN-ACK receive: {e}")
                    finally:
                        self.udp_socket.setblocking(False) # Ensure non-blocking is restored

            except Exception as e:
                log_event(f"Error sending SYN: {e}")
            time.sleep(timeout) # Wait before retry

        log_event(f"Failed to connect to {remote_address} after {retries} retries. Connection aborted.")
        del self.active_connections[remote_address] # Clean up
        raise ConnectionRefusedError(f"Could not connect to {remote_address}")

    def close(self):
        """
        Closes the listening socket on the server or the client's main socket.
        """
        log_event("Closing main socket.")
        self._running = False
        if self.listening_thread and self.listening_thread.is_alive():
            self.listening_thread.join(timeout=1) # Give a short time for the thread to finish

        for addr, conn in list(self.active_connections.items()):
            log_event(f"Closing active connection {addr} during main socket close.")
            conn.close() # Initiate FIN handshake for each active connection
            # Potentially wait for them to fully close (e.g., TIME_WAIT)

        # Handle connections in accept queue (for scoring item 3)
        while not self.accept_queue.empty():
            conn_in_queue, addr_in_queue = self.accept_queue.get_nowait()
            log_event(f"Closing pending connection in accept queue from {addr_in_queue}.")
            # Send FIN to these connections as well
            # For simplicity, just mark them as closed
            conn_in_queue._stop_connection_threads() # Ensure their threads are stopped

        self.udp_socket.close() # Close the underlying UDP socket
        log_event("Main socket closed.")
        
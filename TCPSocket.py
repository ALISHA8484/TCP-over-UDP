import threading
import socket # For UDP socket operation
import time
import struct
import queue # For accept queue
from Packet import Packet, log_event , MSS # Importing Packet and log_event from the Packet module
from Connection import Connection # Importing Connection class for managing individual connections
import random # For generating random sequence numbers

# --- Socket Class ---
class TCPSocket:
    def __init__(self):
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp_socket.setblocking(False) 
        self.is_listening = False
        self.accept_queue = queue.Queue()
        self.active_connections = {} # {remote_addr: Connection_object}
        
        self.listening_thread = None # This thread will now run for both server and client
        self._running = False

    def bind(self, address):
        self.udp_socket.bind(address)
        log_event(f"Socket bound to {address}")

    def listen(self, backlog):
        self.is_listening = True
        self.max_backlog = backlog
        log_event(f"Socket listening with backlog {backlog}")
        self._start_listening_thread() # Start the unified listening thread

    def _start_listening_thread(self):
        if not self._running:
            self._running = True
            self.listening_thread = threading.Thread(target=self._listen_loop)
            self.listening_thread.daemon = True
            self.listening_thread.start()
            log_event(f"Listening thread started on {self.udp_socket.getsockname()}")


    def _listen_loop(self):
        while self._running:
            try:
                # Max possible UDP packet size is about 65507 bytes (65535 - IP_HDR - UDP_HDR)
                # But we are using MSS + HEADER_SIZE. Let's use a generous buffer for safety.
                # max_packet_size = MSS + struct.calcsize(Packet.HEADER_FORMAT_ACTUAL) + 100 # A little extra buffer
                # Changed to 4096 (common socket buffer size) for robustness in receiving.
                # data, addr = self.udp_socket.recvfrom(max_packet_size)
                data, addr = self.udp_socket.recvfrom(4096) # Use 4096 for general receive
                packet = Packet.from_bytes(data)
                log_event(f"Received UDP packet from {addr}: {packet}")

                # --- NEW: Check for packets to unhandled existing connections first ---
                # A connection might exist but not be in active_connections map if it's
                # in a transient state during handshake or needs re-association.
                # This logic is vital for proper demultiplexing.

                # Determine which Connection object this packet belongs to
                target_conn = None
                if addr in self.active_connections:
                    target_conn = self.active_connections[addr]
                
                # --- Handshake and Dispatch Logic ---
                if target_conn: # Packet for an existing connection (or one in handshake)
                    if target_conn.state == "SYN_RCVD" and packet.is_ack() and \
                       packet.ack_num == (target_conn.initial_seq_num + 1) and \
                       packet.seq_num == (target_conn.peer_initial_seq_num + 1):
                        
                        log_event(f"Received final ACK from {addr}. Connection ESTABLISHED.")
                        
                        target_conn.my_seq_num = target_conn.initial_seq_num + 1 
                        target_conn.last_acked_seq = packet.ack_num 

                        log_event(f"Server updated my_seq_num to {target_conn.my_seq_num} and last_acked_seq to {target_conn.last_acked_seq} after final ACK.")

                        target_conn.state = "ESTABLISHED"
                        target_conn._start_connection_threads()
                        self.accept_queue.put((target_conn, addr)) # Make it available to the application via accept()
                    else:
                        # For ALL other packets belonging to this active connection (data, FIN, RST, other ACKs)
                        # Pass them to the connection's handler via its internal queue.
                        log_event(f"DEBUG_LISTEN_LOOP: Queuing packet for connection {addr}, state: {target_conn.state}. Packet: {packet}")
                        target_conn.incoming_packet_queue.put(packet) # Put packet into connection's queue
                
                elif packet.is_syn() and self.is_listening: # New SYN request (only if listening as server)
                    if self.accept_queue.qsize() < self.max_backlog:
                        log_event(f"Received SYN from {addr}. Initiating 3-way handshake.")
                        new_conn = Connection(self.udp_socket, addr, is_server=True)
                        new_conn.peer_initial_seq_num = packet.seq_num 
                        new_conn.next_expected_seq = packet.seq_num + 1 

                        syn_ack_packet = Packet(self.udp_socket.getsockname()[1], addr[1],
                                                new_conn.initial_seq_num, new_conn.next_expected_seq,
                                                Packet.SYN | Packet.ACK, new_conn.receive_window_size)
                        self.udp_socket.sendto(syn_ack_packet.to_bytes(), addr)
                        log_event(f"Sent SYN-ACK to {addr}. Seq={syn_ack_packet.seq_num}, Ack={syn_ack_packet.ack_num}")
                        
                        self.active_connections[addr] = new_conn # Store the half-open connection
                        new_conn.state = "SYN_RCVD" # Set state after storing
                    else:
                        log_event(f"SYN from {addr} rejected: backlog full.")
                        rst_packet = Packet(self.udp_socket.getsockname()[1], addr[1], 0, 0, Packet.RST)
                        self.udp_socket.sendto(rst_packet.to_bytes(), addr)
                
                else: # Unrecognized packet (not for active conn, not a new SYN)
                    log_event(f"Received unrecognized/invalid packet from {addr}: {packet}. Sending RST.")
                    rst_packet = Packet(self.udp_socket.getsockname()[1], addr[1], 0, 0, Packet.RST)
                    self.udp_socket.sendto(rst_packet.to_bytes(), addr)

            except socket.error as e:
                # On Windows, 10035 is WSAEWOULDBLOCK, which means no data. Expected for non-blocking.
                if e.errno == 10035: 
                    pass 
                else:
                    log_event(f"Socket error in listen loop: {e}")
            except ValueError as e:
                log_event(f"Packet parsing error: {e}. Data: {data[:50] if 'data' in locals() else 'N/A'}") # Log data for debug
            except Exception as e:
                log_event(f"Unexpected error in listen loop: {e}")
            time.sleep(0.001) # Small sleep to prevent 100% CPU usage for fast loops, adjust as needed

    def accept(self):
        log_event("Waiting for incoming connection (blocking on accept).")
        conn, addr = self.accept_queue.get() 
        log_event(f"Accepted connection from {addr}.")
        return conn, addr

    def connect(self, remote_address):
        log_event(f"Attempting to connect to {remote_address}...")

        self.udp_socket.bind(('0.0.0.0', 0)) 
        log_event(f"Client socket bound to {self.udp_socket.getsockname()}")

        
        client_src_port = 0 
        conn = Connection(self.udp_socket, remote_address) 
        self.active_connections[remote_address] = conn

        self._start_listening_thread() # Start the unified listening thread for client too!
                                       # This ensures client can receive ACKs / data.

        # Step 1: Send SYN
        syn_packet = Packet(client_src_port, remote_address[1],
                            conn.initial_seq_num, 0, Packet.SYN) 
        
        conn.state = "SYN_SENT"
        retries = 5 
        timeout = 2 
        
        for i in range(retries):
            try:
                self.udp_socket.sendto(syn_packet.to_bytes(), remote_address)
                log_event(f"Sent SYN to {remote_address} (Attempt {i+1}). Seq={syn_packet.seq_num}")

                # Wait for SYN-ACK by polling the connection's incoming_packet_queue
                start_time = time.time()
                syn_ack_received = False
                while time.time() - start_time < timeout:
                    try:
                        # Fetch from this connection's queue, not directly from UDP socket
                        resp_packet = conn.incoming_packet_queue.get(timeout=0.1) 
                        if resp_packet.is_syn() and resp_packet.is_ack() and resp_packet.ack_num == (conn.initial_seq_num + 1):
                            log_event(f"Received SYN-ACK from {remote_address}. Seq={resp_packet.seq_num}, Ack={resp_packet.ack_num}")
                            syn_ack_received = True
                            break
                        else:
                            # Put back to queue if not expected SYN-ACK, or handle as out-of-order/unexpected
                            log_event(f"Received unexpected packet during SYN_SENT: {resp_packet}. Putting back or discarding.")
                            # For robustness, you might need to put it back if it's a valid packet for later
                            # But for simplicity during handshake, discard unexpected.
                    except queue.Empty:
                        pass # No packet yet, continue waiting
                
                if syn_ack_received:
                    conn.peer_initial_seq_num = resp_packet.seq_num
                    conn.next_expected_seq = resp_packet.seq_num + 1 
                    
                    conn.my_seq_num = conn.initial_seq_num + 1 
                    conn.last_acked_seq = resp_packet.ack_num 

                    log_event(f"Client updated my_seq_num to {conn.my_seq_num} and last_acked_seq to {conn.last_acked_seq} after SYN-ACK.")
                    
                    conn.state = "ESTABLISHED"

                    # Step 3: Send final ACK
                    actual_client_src_port = self.udp_socket.getsockname()[1] 
                    ack_packet = Packet(actual_client_src_port, remote_address[1],
                                        conn.my_seq_num, conn.next_expected_seq, Packet.ACK) 
                    self.udp_socket.sendto(ack_packet.to_bytes(), remote_address)
                    log_event(f"Sent final ACK to {remote_address}. Seq={ack_packet.seq_num}, Ack={ack_packet.ack_num}")
                    
                    conn._start_connection_threads() # Start send/receive loops in the connection
                    return conn # Connection established
                else: # Timeout or unexpected packet during SYN_SENT
                    log_event(f"Did not receive expected SYN-ACK within timeout from {remote_address}.")

            except Exception as e:
                log_event(f"Error sending SYN or during handshake: {e}")
            time.sleep(timeout) 

        log_event(f"Failed to connect to {remote_address} after {retries} retries. Connection aborted.")
        del self.active_connections[remote_address]
        raise ConnectionRefusedError(f"Could not connect to {remote_address}")

    def close(self):
        log_event("Closing main socket.")
        self._running = False # Stop the _listen_loop

        if self.listening_thread and self.listening_thread.is_alive():
            self.listening_thread.join(timeout=1) # Wait for listener thread to finish

        for addr, conn in list(self.active_connections.items()):
            log_event(f"Initiating close for active connection {addr} during main socket close.")
            conn.close() # Initiate FIN handshake for each active connection
            # Wait for connection to fully close (e.g., TIME_WAIT) before really cleaning up
            # For simplicity, we just trigger close and let daemon threads handle exit.
        
        # Clear any pending connections in the accept queue
        while not self.accept_queue.empty():
            conn_in_queue, _ = self.accept_queue.get_nowait()
            log_event(f"Closing pending connection in accept queue.")
            conn_in_queue._stop_connection_threads()

        self.udp_socket.close()
        log_event("Main socket closed.")

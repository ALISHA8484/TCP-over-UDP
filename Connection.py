import threading
import socket # For UDP socket operation
import time
import random
import Packet
import queue # For accept queue
from Packet import Packet, log_event , MSS 

# --- Connection Class ---
class Connection:
    """
    Represents an active TCP-like connection.
    Manages send/receive buffers, sequence numbers, acknowledgments,
    sliding windows, and connection state.
    """
    def __init__(self, udp_socket, remote_addr, is_server=False):

        self.udp_socket = udp_socket
        self.remote_addr = remote_addr # (ip, port) of the remote peer
        self.is_server = is_server

        self.state = "CLOSED" # Initial state: CLOSED, LISTEN, SYN_SENT, SYN_RCVD, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT, LAST_ACK, TIME_WAIT
        
        # Sequence and Acknowledgment numbers
        self.my_seq_num = random.randint(0, 2**32 - 1)
        self.peer_seq_num = 0
        self.peer_ack_num = 0
        self.next_expected_seq = 0
        
        # Buffers
        self.send_buffer = b"" # Data waiting to be sent
        self.receive_buffer = b"" # Data received but not yet read by application
        
        # Sliding Window parameters
        self.send_window_size = 128
        self.receive_window_size = 128
        self.last_acked_seq = self.my_seq_num # The sequence number of the last byte acknowledged by the peer
        self.send_unacked_packets = {} # Dictionary to store packets sent but not yet ACKed: {seq_num: (packet, timestamp)}
        
        # Flow Control and Congestion Control variables (for scoring items)
        self.rwnd = self.receive_window_size # Receive Window - based on peer's available buffer space 
        self.cwnd = MSS # Congestion Window - initially MSS
        self.effective_send_window = min(self.send_window_size, self.rwnd, self.cwnd)
        
        # Fast Retransmit specific variables
        self.duplicate_acks = 0 # Counter for duplicate ACKs 
        self.retransmit_seq_on_dup_ack = None # Sequence number to retransmit on 3rd dup ACK

        # Timers (for scoring items)
        self.retransmission_timer = None
        self.retransmission_timeout = 1.0
        self.keep_alive_timer = None
        self.connection_timeout = 60 # Seconds until connection auto-closes if idle

        # Threads for sending/receiving logic
        self.send_thread = threading.Thread(target=self._send_loop)
        self.receive_thread = threading.Thread(target=self._receive_loop) # This thread processes already received data for this connection
        self._running = False

    def _start_connection_threads(self):
        """Starts the background threads for sending and receiving logic."""
        if not self._running:
            self._running = True
            self.send_thread.daemon = True # Daemon threads exit when the main program exits
            self.receive_thread.daemon = True
            self.send_thread.start()
            self.receive_thread.start()
            log_event(f"Connection threads started for {self.remote_addr}")

    def _stop_connection_threads(self):
        """Stops the background threads."""
        if self._running:
            self._running = False
            # Implement graceful shutdown for threads if needed
            log_event(f"Connection threads stopped for {self.remote_addr}")

    def _send_loop(self):
        """
        Background thread for managing the send buffer and transmitting packets.
        Handles retransmissions, sliding window updates.
        """
        while self._running:
            # Check if there's data in the send buffer and space in the window
            if self.send_buffer and len(self.send_buffer) > (self.my_seq_num - self.last_acked_seq) and (self.my_seq_num - self.last_acked_seq) < self.effective_send_window:

                data_to_send = self.send_buffer[self.my_seq_num - self.last_acked_seq : self.my_seq_num - self.last_acked_seq + MSS]
                
                # Create and send packet
                packet = Packet(self.udp_socket.getsockname()[1], self.remote_addr[1], 
                                self.my_seq_num, self.next_expected_seq, Packet.ACK,
                                self.receive_window_size, data_to_send)
                try:
                    self.udp_socket.sendto(packet.to_bytes(), self.remote_addr)
                    log_event(f"Sent data packet to {self.remote_addr}: Seq={packet.seq_num}, Len={len(data_to_send)}")
                    self.send_unacked_packets[packet.seq_num] = (packet, time.time()) # Store for retransmission
                    self.my_seq_num += len(data_to_send) # Advance my sequence number
                except Exception as e:
                    log_event(f"Error sending data packet: {e}")

            # Handle retransmissions for unacknowledged packets
            current_time = time.time()
            for seq, (packet, send_time) in list(self.send_unacked_packets.items()):
                if current_time - send_time > self.retransmission_timeout:
                    log_event(f"Retransmitting packet {packet.seq_num} to {self.remote_addr} due to timeout.")
                    try:
                        self.udp_socket.sendto(packet.to_bytes(), self.remote_addr)
                        self.send_unacked_packets[seq] = (packet, current_time) # Update send time
                        # Congestion control: Timeout leads to cwnd = MSS
                        self.cwnd = MSS 
                        self.effective_send_window = min(self.send_window_size, self.rwnd, self.cwnd)
                    except Exception as e:
                        log_event(f"Error retransmitting packet: {e}") # [cite: 1]

            time.sleep(0.01) # Small delay to prevent busy-waiting

    def _receive_loop(self):
        """
        Background thread for processing received packets for this specific connection.
        Handles acknowledgments, out-of-order packets, and updates receive window.
        Note: The actual UDP reception (sock.recvfrom) is done by the Socket's main receive thread.
        This loop processes data *after* it has been demultiplexed to this connection.
        """
        while self._running:
            # This loop would typically process a queue of received packets specific to this connection
            # that were put there by the main Socket's receive thread.
            # For simplicity, let's assume raw packets are passed directly for now.
            # In a full implementation, you'd have a queue like `self.incoming_packet_queue`.

            # This part needs careful design: where do packets for *this specific connection* arrive?
            # They should be put into a connection-specific queue by the main socket's listener thread.

            # Placeholder for processing logic (this will be complex)
            # When a packet is received for this connection:
            # 1. Check sequence number and flags.
            # 2. If it's an ACK: update self.last_acked_seq, remove from self.send_unacked_packets,
            #    and update send window, cwnd (for congestion control). [cite: 79, 80, 81]
            # 3. If it's data: add to receive buffer, handle out-of-order, send ACK. [cite: 62, 85, 88]
            # 4. If it's FIN: initiate connection close.
            # 5. If it's RST: immediate connection reset.
            pass # Implement packet processing logic here

    def handle_incoming_packet(self, packet):
        """
        Called by the Socket's main receive thread when a packet
        is identified for this connection.
        """
        log_event(f"Received packet for {self.remote_addr}: {packet}")

        if packet.is_ack():
            # Check if this ACK acknowledges new data
            if packet.ack_num > self.last_acked_seq:
                # ... (Existing logic for new ACK, updating last_acked_seq, removing from unacked_packets, increasing cwnd)
                # Reset duplicate ACK counter on new ACK
                self.duplicate_acks = 0
                self.retransmit_seq_on_dup_ack = None

            else: # packet.ack_num <= self.last_acked_seq
                # This is a duplicate ACK (for scoring item 11) 
                log_event(f"Received duplicate ACK for Seq {packet.ack_num}. Current last_acked_seq: {self.last_acked_seq}")
                self.duplicate_acks += 1

                # Set the sequence number to retransmit if it's the first duplicate ACK for this segment
                if self.duplicate_acks == 1:
                    # Find the smallest (oldest) unacknowledged sequence number
                    if self.send_unacked_packets: # Ensure there are unacked packets
                        self.retransmit_seq_on_dup_ack = min(self.send_unacked_packets.keys())
                    log_event(f"First duplicate ACK. Target for Fast Retransmit: {self.retransmit_seq_on_dup_ack}")

                # Fast Retransmit: if 3 duplicate ACKs are received 
                if self.duplicate_acks >= 3:
                    if self.retransmit_seq_on_dup_ack is not None and self.retransmit_seq_on_dup_ack in self.send_unacked_packets:
                        log_event(f"3 Duplicate ACKs received. Performing Fast Retransmit for Seq {self.retransmit_seq_on_dup_ack}.") [cite: 1]

                        # Retransmit the segment corresponding to retransmit_seq_on_dup_ack
                        packet_to_retransmit, _ = self.send_unacked_packets[self.retransmit_seq_on_dup_ack]
                        try:
                            self.udp_socket.sendto(packet_to_retransmit.to_bytes(), self.remote_addr)
                            self.send_unacked_packets[packet_to_retransmit.seq_num] = (packet_to_retransmit, time.time()) # Update send time

                            # Congestion control: cwnd halved on 3 duplicate ACKs 
                            self.cwnd = max(MSS, self.cwnd // 2) # Ensure cwnd is at least MSS
                            log_event(f"CWND halved to {self.cwnd} due to 3 duplicate ACKs.")
                            self.effective_send_window = min(self.send_window_size, self.rwnd, self.cwnd) [cite: 1]

                            # Reset duplicate ACKs after retransmission (important)
                            self.duplicate_acks = 0
                            self.retransmit_seq_on_dup_ack = None

                        except Exception as e:
                            log_event(f"Error during Fast Retransmit: {e}")
                    else:
                        log_event("Fast Retransmit triggered but target packet not found or already retransmitted/acked.")
    
        if packet.payload_length > 0:
            # Acknowledge the received data payload
            # This part needs robust out-of-order handling and receive buffer management.
            # For now, we assume in-order delivery for simplicity in this snippet.
            
            # Check if this is the next expected sequence number
            if packet.seq_num == self.next_expected_seq:
                self.receive_buffer += packet.payload
                self.next_expected_seq += packet.payload_length # Advance expected sequence number
                log_event(f"Received in-order data. New next_expected_seq: {self.next_expected_seq}")
                
                # Send ACK for received data
                ack_packet = Packet(self.udp_socket.getsockname()[1], self.remote_addr[1],
                                    self.my_seq_num, self.next_expected_seq, Packet.ACK,
                                    len(self.receive_buffer)) # Send current receive window size
                try:
                    self.udp_socket.sendto(ack_packet.to_bytes(), self.remote_addr)
                    log_event(f"Sent ACK for data to {self.remote_addr}: Ack={ack_packet.ack_num}, Window={ack_packet.window_size}")
                except Exception as e:
                    log_event(f"Error sending ACK for data: {e}")

            else: # packet.seq_num != self.next_expected_seq (out-of-order)
                log_event(f"Received out-of-order packet: Expected Seq {self.next_expected_seq}, got {packet.seq_num}.")
                # Store out-of-order packets and send duplicate ACK for the last in-order byte.
                # This part requires a more sophisticated receive buffer for reordering.
                # For now, we just log it and send a duplicate ACK for the current next_expected_seq.

                # Send a duplicate ACK for the last correctly received byte
                ack_packet = Packet(self.udp_socket.getsockname()[1], self.remote_addr[1],
                                    self.my_seq_num, self.next_expected_seq, Packet.ACK,
                                    len(self.receive_buffer)) # Send current receive window size
                try:
                    self.udp_socket.sendto(ack_packet.to_bytes(), self.remote_addr)
                    log_event(f"Sent Duplicate ACK for out-of-order packet. Ack={ack_packet.ack_num}, Window={ack_packet.window_size}")
                except Exception as e:
                    log_event(f"Error sending Duplicate ACK: {e}")

        # Handle FIN flag
        if packet.is_fin():
            log_event(f"Received FIN from {self.remote_addr}. Initiating close process.")
            self.state = "CLOSE_WAIT" # Or FIN_WAIT_2 depending on where you are in the 4-way handshake
            # Send ACK for FIN
            ack_fin_packet = Packet(self.udp_socket.getsockname()[1], self.remote_addr[1],
                                    self.my_seq_num, packet.seq_num + 1, Packet.ACK | Packet.FIN, # ACK for FIN, and send our own FIN
                                    self.receive_window_size)
            try:
                self.udp_socket.sendto(ack_fin_packet.to_bytes(), self.remote_addr)
                log_event(f"Sent ACK+FIN to {self.remote_addr} in response to FIN.")
            except Exception as e:
                log_event(f"Error sending ACK+FIN: {e}")
            self._stop_connection_threads() # Stop threads for this connection

        # Handle RST flag
        if packet.is_rst():
            log_event(f"Received RST from {self.remote_addr}. Connection reset.")
            self.state = "CLOSED"
            self._stop_connection_threads()


    def send(self, data):
        """
        Adds data to the send buffer. Data is actually sent by the _send_loop thread. 
        Blocks if the send buffer is full (though for this project, send buffer has no capacity limit).
        """
        log_event(f"Application requested to send {len(data)} bytes to {self.remote_addr}.")
        self.send_buffer += data
        # The send_loop will pick this up and send it

    def receive(self, buffer_size):
        """
        Retrieves data from the receive buffer. Blocks if not enough data. 
        """
        log_event(f"Application requested to receive {buffer_size} bytes from {self.remote_addr}.")
        
        while len(self.receive_buffer) < buffer_size:
            if not self._running and len(self.receive_buffer) == 0:
                log_event(f"Connection with {self.remote_addr} is closed and no data in buffer.")
                return b'' # Connection closed, no more data
            log_event(f"Not enough data in receive buffer ({len(self.receive_buffer)}/{buffer_size} bytes). Blocking...")
            time.sleep(0.1) # Simulate blocking
        
        data = self.receive_buffer[:buffer_size]
        self.receive_buffer = self.receive_buffer[buffer_size:]
        
        # After data is read, update receive window (for scoring item 9) [cite: 62]
        self.receive_window_size = 128 # Re-adjust based on actual buffer space
        # A more complex implementation would calculate actual available space in the receive buffer
        
        log_event(f"Application received {len(data)} bytes from {self.remote_addr}.") # [cite: 1]
        return data

    def close(self):
        """
        Initiates the connection termination process (FIN handshake).
        """
        log_event(f"Initiating connection close for {self.remote_addr}.") # [cite: 1]
        if self.state == "ESTABLISHED":
            self.state = "FIN_WAIT_1"
            fin_packet = Packet(self.udp_socket.getsockname()[1], self.remote_addr[1],
                                self.my_seq_num, self.next_expected_seq, Packet.FIN,
                                self.receive_window_size)
            try:
                self.udp_socket.sendto(fin_packet.to_bytes(), self.remote_addr)
                log_event(f"Sent FIN to {self.remote_addr}.")
                # Start a timer for FIN_WAIT_1 ACK
                # If ACK not received, retransmit FIN
            except Exception as e:
                log_event(f"Error sending FIN: {e}")
        
        self._stop_connection_threads() # Stop threads, but keep the object until fully closed from TCP perspective


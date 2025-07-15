import threading
import socket # For UDP socket operation
import time
import random
import struct
import Packet
import queue # For accept queue
from Packet import Packet, log_event , MSS 

# --- Connection Class ---
class Connection:
    def __init__(self, udp_socket, remote_addr, is_server=False):
        self.udp_socket = udp_socket
        self.remote_addr = remote_addr
        self.is_server = is_server

        self.state = "CLOSED"
        
        self.initial_seq_num = random.randint(0, 2**32 - 1)
        self.my_seq_num = self.initial_seq_num
        self.last_acked_seq = self.initial_seq_num

        self.peer_initial_seq_num = 0
        self.peer_ack_num = 0
        self.next_expected_seq = 0

        self.send_buffer = b""
        self.receive_buffer = b""
        
        self.send_window_size = 128
        self.receive_window_size = 128 # This can be dynamic based on receive_buffer free space
        
        self.send_unacked_packets = {} 
        
        self.rwnd = self.receive_window_size 
        self.cwnd = MSS 
        self.effective_send_window = min(self.send_window_size, self.rwnd, self.cwnd)
        
        self.duplicate_acks = 0
        self.retransmit_seq_on_dup_ack = None

        self.retransmission_timeout = 1.0 
        self.retransmission_timer = None 
        self.keep_alive_timer = None
        self.connection_timeout = 60

        # --- NEW for cleaner receive logic ---
        self.incoming_packet_queue = queue.Queue() # Queue for packets received by TCPSocket._listen_loop for THIS connection
        # --- END NEW ---

        self.send_thread = threading.Thread(target=self._send_loop)
        self.receive_thread = threading.Thread(target=self._receive_loop) 
        self._running = False

    def _start_connection_threads(self):
        if not self._running:
            self._running = True
            self.send_thread.daemon = True
            self.receive_thread.daemon = True
            self.send_thread.start()
            self.receive_thread.start()
            log_event(f"Connection threads started for {self.remote_addr}")

    def _stop_connection_threads(self):
        if self._running:
            self._running = False
            log_event(f"Connection threads stopped for {self.remote_addr}")
            # Clear the queue to prevent hanging if there are unprocessed packets
            while not self.incoming_packet_queue.empty():
                try:
                    self.incoming_packet_queue.get_nowait()
                except queue.Empty:
                    break


    def _send_loop(self):
        while self._running:
            bytes_in_flight = self.my_seq_num - self.last_acked_seq
            
            # --- DEBUG LOG ---
            log_event(f"DEBUG_SEND_LOOP: MySeq={self.my_seq_num}, LastAckedSeq={self.last_acked_seq}, "
                      f"BytesInFlight={bytes_in_flight}, SendBufferLen={len(self.send_buffer)}, "
                      f"EffectiveWindow={self.effective_send_window}")
            # --- END DEBUG LOG ---

            available_window_space = self.effective_send_window - bytes_in_flight
            
            send_size = min(len(self.send_buffer), available_window_space, MSS)
            
            if send_size > 0:
                data_to_send = self.send_buffer[:send_size] 

                packet = Packet(self.udp_socket.getsockname()[1], self.remote_addr[1], 
                                self.my_seq_num, self.next_expected_seq, Packet.ACK, # Always include ACK flag for data packets
                                self.receive_window_size, data_to_send)
                try:
                    self.udp_socket.sendto(packet.to_bytes(), self.remote_addr)
                    log_event(f"Sent data packet to {self.remote_addr}: Seq={packet.seq_num}, Len={len(data_to_send)}, Bytes in flight: {bytes_in_flight + len(data_to_send)}")
                    
                    self.send_unacked_packets[packet.seq_num] = (packet, time.time())
                    self.my_seq_num += len(data_to_send) 

                except Exception as e:
                    log_event(f"Error sending data packet: {e}")

            # Handle retransmissions for unacknowledged packets
            current_time = time.time()
            for seq, (packet, send_time) in list(self.send_unacked_packets.items()):
                if current_time - send_time > self.retransmission_timeout:
                    log_event(f"Retransmitting packet {packet.seq_num} to {self.remote_addr} due to timeout.")
                    try:
                        self.udp_socket.sendto(packet.to_bytes(), self.remote_addr)
                        # Do NOT update timestamp here for retransmission, or update only if you implement RTT estimation
                        # For a simple RTO, keep original timestamp or use a separate retransmit counter
                        # self.send_unacked_packets[seq] = (packet, current_time) # Optional: update timestamp for next retransmission
                        
                        self.cwnd = MSS
                        log_event(f"CWND reset to {self.cwnd} due to timeout.")
                        self.effective_send_window = min(self.send_window_size, self.rwnd, self.cwnd)
                        self.duplicate_acks = 0
                        self.retransmit_seq_on_dup_ack = None

                    except Exception as e:
                        log_event(f"Error retransmitting packet: {e}")

            time.sleep(0.01)

    def _receive_loop(self):
        """
        Background thread for processing packets from the incoming_packet_queue.
        These packets are already received by TCPSocket._listen_loop and demultiplexed.
        """
        while self._running:
            try:
                # Get packet from queue (blocking with a timeout)
                packet = self.incoming_packet_queue.get(timeout=0.1) 
                self.handle_incoming_packet(packet) # Process the packet
            except queue.Empty:
                pass # No packet in queue, continue loop
            except Exception as e:
                log_event(f"[RECEIVE_LOOP_ERROR] Error processing packet from queue: {e}") 
            # No sleep here, as queue.get(timeout) provides the necessary delay

    def handle_incoming_packet(self, packet):
        log_event(f"Received packet for {self.remote_addr}: {packet}")

        if packet.is_rst():
            log_event(f"Received RST from {self.remote_addr}. Connection reset.")
            self.state = "CLOSED"
            self._stop_connection_threads()
            return

        # --- Process ACK segment ---
        if packet.is_ack():
            if packet.ack_num > self.last_acked_seq:
                log_event(f"ACK received for Seq up to {packet.ack_num}. Moving send window.")
                
                newly_acked_bytes = packet.ack_num - self.last_acked_seq
                
                if newly_acked_bytes > 0:
                    self.send_buffer = self.send_buffer[newly_acked_bytes:]
                    log_event(f"Removed {newly_acked_bytes} bytes from send_buffer. Remaining: {len(self.send_buffer)}")

                self.last_acked_seq = packet.ack_num 
                
                keys_to_remove = []
                for seq_num, (sent_packet, send_time) in list(self.send_unacked_packets.items()):
                    if (sent_packet.seq_num + sent_packet.payload_length) <= packet.ack_num: 
                        keys_to_remove.append(seq_num)
                for key in keys_to_remove:
                    del self.send_unacked_packets[key]
                
                self.cwnd += MSS 
                log_event(f"CWND increased to {self.cwnd} due to new ACK.")
                self.effective_send_window = min(self.send_window_size, self.rwnd, self.cwnd)

                self.duplicate_acks = 0
                self.retransmit_seq_on_dup_ack = None

            else: # packet.ack_num <= self.last_acked_seq (duplicate ACK logic)
                log_event(f"Received duplicate ACK for Seq {packet.ack_num}. Current last_acked_seq: {self.last_acked_seq}")
                self.duplicate_acks += 1
                
                if self.duplicate_acks == 1:
                    if self.send_unacked_packets:
                        self.retransmit_seq_on_dup_ack = min(self.send_unacked_packets.keys())
                    log_event(f"First duplicate ACK. Target for Fast Retransmit: {self.retransmit_seq_on_dup_ack}")

                if self.duplicate_acks >= 3:
                    if self.retransmit_seq_on_dup_ack is not None and self.retransmit_seq_on_dup_ack in self.send_unacked_packets:
                        log_event(f"3 Duplicate ACKs received. Performing Fast Retransmit for Seq {self.retransmit_seq_on_dup_ack}.")
                        
                        packet_to_retransmit, _ = self.send_unacked_packets[self.retransmit_seq_on_dup_ack]
                        try:
                            self.udp_socket.sendto(packet_to_retransmit.to_bytes(), self.remote_addr)
                            # self.send_unacked_packets[packet_to_retransmit.seq_num] = (packet_to_retransmit, time.time()) # Optional: update timestamp
                            
                            self.cwnd = max(MSS, self.cwnd // 2) 
                            log_event(f"CWND halved to {self.cwnd} due to 3 duplicate ACKs.")
                            self.effective_send_window = min(self.send_window_size, self.rwnd, self.cwnd)
                            
                            self.duplicate_acks = 0
                            self.retransmit_seq_on_dup_ack = None
                            
                        except Exception as e:
                            log_event(f"Error during Fast Retransmit: {e}")
                    else:
                        log_event("Fast Retransmit triggered but target packet not found or already retransmitted/acked.")

            self.rwnd = packet.window_size
            self.effective_send_window = min(self.send_window_size, self.rwnd, self.cwnd)

        # --- Process Data Payload ---
        if packet.payload_length > 0:
            log_event(f"DEBUG_HANDLE_DATA: Processing data packet. Seq={packet.seq_num}, Expected={self.next_expected_seq}, PayloadLen={packet.payload_length}")
            
            # This is where sophisticated out-of-order buffering would go.
            # For now, append only if in-order.
            if packet.seq_num == self.next_expected_seq:
                self.receive_buffer += packet.payload
                self.next_expected_seq += packet.payload_length 
                log_event(f"Received in-order data. New next_expected_seq: {self.next_expected_seq}")
                
                ack_packet = Packet(self.udp_socket.getsockname()[1], self.remote_addr[1],
                                    self.my_seq_num, self.next_expected_seq, Packet.ACK,
                                    self.receive_window_size) 
                try:
                    self.udp_socket.sendto(ack_packet.to_bytes(), self.remote_addr)
                    log_event(f"Sent ACK for data to {self.remote_addr}: Ack={ack_packet.ack_num}, Window={ack_packet.window_size}")
                except Exception as e:
                    log_event(f"Error sending ACK for data: {e}")

            else: 
                log_event(f"Received out-of-order packet: Expected Seq {self.next_expected_seq}, got {packet.seq_num}.")
                
                ack_packet = Packet(self.udp_socket.getsockname()[1], self.remote_addr[1],
                                    self.my_seq_num, self.next_expected_seq, Packet.ACK,
                                    self.receive_window_size) 
                try:
                    self.udp_socket.sendto(ack_packet.to_bytes(), self.remote_addr)
                    log_event(f"Sent Duplicate ACK for out-of-order packet. Ack={ack_packet.ack_num}, Window={ack_packet.window_size}")
                except Exception as e:
                    log_event(f"Error sending Duplicate ACK: {e}")

        # --- Handle FIN flag ---
        if packet.is_fin():
            log_event(f"Received FIN from {self.remote_addr}. Initiating close process.")
            if self.state == "ESTABLISHED": 
                self.state = "CLOSE_WAIT" 
                ack_for_fin_packet = Packet(self.udp_socket.getsockname()[1], self.remote_addr[1],
                                            self.my_seq_num, packet.seq_num + 1, Packet.ACK,
                                            self.receive_window_size)
                try:
                    self.udp_socket.sendto(ack_for_fin_packet.to_bytes(), self.remote_addr)
                    log_event(f"Sent ACK to FIN from {self.remote_addr}.")
                    if not self.send_buffer and not self.send_unacked_packets: 
                        self.close() # Trigger our own FIN
                except Exception as e:
                    log_event(f"Error sending ACK for FIN: {e}")
            elif self.state == "FIN_WAIT_2": 
                log_event(f"Received FIN from {self.remote_addr} while in FIN_WAIT_2. Moving to TIME_WAIT.")
                self.state = "TIME_WAIT"
                final_ack_for_fin = Packet(self.udp_socket.getsockname()[1], self.remote_addr[1],
                                            self.my_seq_num, packet.seq_num + 1, Packet.ACK,
                                            self.receive_window_size)
                try:
                    self.udp_socket.sendto(final_ack_for_fin.to_bytes(), self.remote_addr)
                    log_event(f"Sent final ACK to {self.remote_addr} for their FIN. Entering TIME_WAIT.")
                except Exception as e:
                    log_event(f"Error sending final ACK for FIN: {e}")
                threading.Timer(2 * self.retransmission_timeout, self._close_after_time_wait).start()

        if self.state == "FIN_WAIT_1" and packet.is_ack() and packet.ack_num == (self.my_seq_num): # ACK for our FIN
            log_event(f"Received ACK for our FIN from {self.remote_addr}. Moving to FIN_WAIT_2.")
            self.state = "FIN_WAIT_2"


    def send(self, data):
        log_event(f"Application requested to send {len(data)} bytes to {self.remote_addr}.")
        self.send_buffer += data

    def receive(self, buffer_size):
        log_event(f"Application requested to receive {buffer_size} bytes from {self.remote_addr}.")
        
        while len(self.receive_buffer) < buffer_size:
            if not self._running and len(self.receive_buffer) == 0:
                log_event(f"Connection with {self.remote_addr} is closed and no data in buffer.")
                return b''
            log_event(f"Not enough data in receive buffer ({len(self.receive_buffer)}/{buffer_size} bytes). Blocking...")
            time.sleep(0.01) # Small sleep to prevent busy-waiting while blocking.
        
        data = self.receive_buffer[:buffer_size]
        self.receive_buffer = self.receive_buffer[buffer_size:]
        self.receive_window_size = 128 # In a real implementation, this should reflect actual available buffer size.
        
        log_event(f"Application received {len(data)} bytes from {self.remote_addr}.")
        return data

    def close(self):
        log_event(f"Initiating connection close for {self.remote_addr}.")
        if self.state == "ESTABLISHED" or self.state == "CLOSE_WAIT": # Can close from ESTABLISHED or after receiving FIN
            if self.state == "ESTABLISHED": # Only send FIN if we are still ESTABLISHED
                self.state = "FIN_WAIT_1"
                # FIN consumes 1 sequence number
                fin_packet = Packet(self.udp_socket.getsockname()[1], self.remote_addr[1],
                                    self.my_seq_num, self.next_expected_seq, Packet.FIN,
                                    self.receive_window_size)
                try:
                    self.udp_socket.sendto(fin_packet.to_bytes(), self.remote_addr)
                    log_event(f"Sent FIN to {self.remote_addr}. Seq={fin_packet.seq_num}")
                    self.my_seq_num += 1 # FIN consumes 1 byte of sequence space
                except Exception as e:
                    log_event(f"Error sending FIN: {e}")
            # Do NOT stop connection threads here. They should run until TIME_WAIT or RST.


    def _close_after_time_wait(self):
        log_event(f"Exiting TIME_WAIT state for {self.remote_addr}. Connection fully closed.")
        self.state = "CLOSED"
        self._stop_connection_threads() # Now it's safe to stop the threads

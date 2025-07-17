import time
import sys
import os
import random

from my_tcp_lib import TCPSocket, log_event, MSS, Connection, Packet

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345

def run_client():
    client_socket = None
    try:
        log_event("Client starting.")
        client_socket = TCPSocket()
        
        # Connect to the server
        # This will perform the 3-way handshake
        conn = client_socket.connect((SERVER_HOST, SERVER_PORT)) 
        conn.is_server = False
        log_event(f"Connection established with server at {SERVER_HOST}:{SERVER_PORT}")

        # Simulate sending a large message
        # A large message ensures multiple packets and tests windowing, retransmission, and ACK
        message_prefix = "Hello, this is client data. "
        large_message = b""
        num_chunks = 100 # Increased chunks for more data transfer
        for i in range(num_chunks):
            large_message += f"{message_prefix} chunk {i+1}. This is some dummy data to fill up the buffer. {random.randint(10000, 99999)}.".encode('utf-8')
        
        # Add an end signal to the message
        large_message += b"END_OF_CLIENT_DATA_STREAM"

        log_event(f"Client preparing to send {len(large_message)} bytes of data.")
        conn.send(large_message) 
        log_event("Client finished queuing data to send buffer. It will be sent in background.")

        # Main loop to keep client active during data transfer and handle interrupts
        while len(conn.send_buffer) > 0 or len(conn.unacked_sent_packets) > 0:
            # The loop continues as long as there is data to send or data is in flight
            time.sleep(0.1)

        # All data has been sent and acknowledged, now close the connection
        log_event("All data acknowledged. Initiating connection close.")
        conn.close()
        
        # Keep the client alive for a few seconds to handle the FIN handshake
        time.sleep(5)
        
        log_event("Client has finished its job.")

    except ConnectionRefusedError as e:
        log_event(f"Client connection error: {e}")
    except KeyboardInterrupt:
        log_event("Client shutting down due to user interrupt (Ctrl+C).")
        if 'conn' in locals() and conn.state == 'ESTABLISHED':
            log_event("Sending RST packet to server for abnormal termination.")
            conn.RST_closing = True
            try:
                # Create and send an RST packet
                rst_packet = Packet(conn.udp_socket.getsockname()[1], conn.remote_address[1], 
                                    conn.my_seq_num, conn.next_expected_seq_from_peer, Packet.RST)
                conn.udp_socket.sendto(rst_packet.to_bytes(), conn.remote_address)
                log_event("RST packet sent.")
            except Exception as e:
                log_event(f"Error sending RST packet: {e}")

    except Exception as e:
        log_event(f"An unexpected error occurred in client: {e}")
    finally:
        if client_socket:
            client_socket.close() 
        log_event("Client stopped.")

if __name__ == "__main__":
    run_client()
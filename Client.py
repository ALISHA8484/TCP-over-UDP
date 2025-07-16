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
        log_event(f"Connection established with server at {SERVER_HOST}:{SERVER_PORT}")

        # Simulate sending a large message
        # A large message ensures multiple packets and tests windowing, retransmission, and ACK
        message_to_send = b"Hello, this is a very long message to demonstrate the TCP over UDP protocol. This message is broken into many segments for testing purposes." * 50
        
        log_event(f"Client preparing to send {len(message_to_send)} bytes of data.")
        conn.send(message_to_send) 
        log_event("Client finished queuing data to send buffer. It will be sent in background.")

        # Check if the send buffer is empty, and then close the connection
        log_event("Waiting for all data to be sent and acknowledged.")
        while len(conn.send_buffer) > 0 or len(conn.unacked_sent_packets) > 0:
            time.sleep(0.1)
        
        # All data has been sent and acknowledged, now close the connection
        log_event("All data acknowledged. Initiating connection close.")
        conn.close()

        # Keep the client alive to receive FIN from server and close gracefully
        time.sleep(5) # Wait for server to receive FIN and send back ACK/FIN
        
        log_event("Client has finished its job.")

    except ConnectionRefusedError as e:
        log_event(f"Client connection error: {e}")
    except KeyboardInterrupt:
        log_event("Client shutting down due to user interrupt.")
    except Exception as e:
        log_event(f"An unexpected error occurred in client: {e}")
    finally:
        if client_socket:
            client_socket.close() 
        log_event("Client stopped.")

if __name__ == "__main__":
    run_client()
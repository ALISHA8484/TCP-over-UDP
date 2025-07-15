import time
import sys
import os
import struct
import random

from Packet import log_event, MSS , Packet
from Connection import Connection
from TCPSocket import TCPSocket

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345

def run_client():
    client_socket = None
    try:
        log_event("Client starting.")
        client_socket = TCPSocket()
        
        # Connect to the server [cite: 44]
        # This will perform the 3-way handshake
        conn = client_socket.connect((SERVER_HOST, SERVER_PORT))
        log_event(f"Connection established with server at {SERVER_HOST}:{SERVER_PORT}")

        # Simulate sending a large amount of data [cite: 49]
        message_prefix = "Hello, this is client data. "
        large_message = b""
        num_chunks = 100 # Increased chunks for more data transfer
        for i in range(num_chunks):
            large_message += f"{message_prefix} chunk {i+1}. This is some dummy data to fill up the buffer. {random.randint(10000, 99999)}.".encode('utf-8')
        
        # Add an end signal to the message
        large_message += b"END_OF_CLIENT_DATA_STREAM"

        log_event(f"Client preparing to send {len(large_message)} bytes of data.")
        conn.send(large_message) # This puts data into the send buffer
        log_event("Client finished queuing data to send buffer. It will be sent in background.")

        # Allow some time for data to be sent and acknowledged
        # In a real app, you'd wait for all data to be acknowledged, or for a specific response
        time.sleep(10) # Give send_loop time to process and send

        # Simulate receiving a response from the server [cite: 56]
        log_event("Client waiting for server response...")
        server_response = b""
        total_received_bytes_client = 0
        
        # Receive loop for server's response
        start_time_receive = time.time()
        receive_timeout_client = 15 # seconds
        while time.time() - start_time_receive < receive_timeout_client:
            try:
                data = conn.receive(MSS) # Read in chunks
                if data:
                    server_response += data
                    total_received_bytes_client += len(data)
                    log_event(f"Client received {len(data)} bytes from server. Total: {total_received_bytes_client} bytes.")
                    if b"End of server response" in data:
                        log_event("Client received 'End of server response' signal. Breaking receive loop.")
                        break
                elif conn.state == "CLOSED":
                    log_event("Connection closed by peer during receive on client side.")
                    break
                else:
                    time.sleep(0.01)
            except Exception as e:
                log_event(f"Client receive error: {e}")
                break
        
        log_event(f"Client finished receiving. Total bytes from server: {total_received_bytes_client}")
        if server_response:
            log_event(f"Client received server response: '{server_response.decode('utf-8', errors='ignore')}'")
        else:
            log_event("Client received no response or connection closed prematurely.")

    except ConnectionRefusedError as e:
        log_event(f"Client connection error: {e}")
    except KeyboardInterrupt:
        log_event("Client shutting down due to user interrupt.")
    except Exception as e:
        log_event(f"An unexpected error occurred in client: {e}")
    finally:
        if client_socket:
            client_socket.close() # Ensure socket is closed on exit [cite: 66, 67]
        log_event("Client stopped.")

if __name__ == "__main__":
    run_client()
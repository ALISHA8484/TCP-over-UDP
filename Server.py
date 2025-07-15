import time
import sys
import os
import struct
from Packet import log_event, MSS , Packet
from Connection import Connection
from TCPSocket import TCPSocket

SERVER_HOST = '127.0.0.1' # Listen on localhost
SERVER_PORT = 12345       # Arbitrary port

def run_server():
    server_socket = None
    try:
        log_event(f"Server starting on {SERVER_HOST}:{SERVER_PORT}")
        server_socket = TCPSocket()
        server_socket.bind((SERVER_HOST, SERVER_PORT))
        server_socket.listen(5) # Max 5 pending connections in backlog

        log_event("Waiting for connections...")
        # accept() will block until a connection is established
        conn, addr = server_socket.accept() 
        log_event(f"Connection established with {addr}")

        # Simulate receiving data from client
        received_data = b""
        total_received_bytes = 0
        
        log_event("Server receiving data...")
        # Receive loop: receive data in chunks
        start_time = time.time()
        # Set a timeout for the server to wait for data (for robust testing)
        receive_timeout = 30 # seconds
        
        while time.time() - start_time < receive_timeout:
            try:
                # Try to read up to MSS bytes at a time [cite: 57]
                # conn.receive() will block if no data, or return b'' if connection closes cleanly
                data = conn.receive(MSS) 
                if data:
                    received_data += data
                    total_received_bytes += len(data)
                    log_event(f"Server received {len(data)} bytes. Total: {total_received_bytes} bytes.")
                    # Check for end signal
                    if b"end_of_transfer" in data: # It's better to check per-chunk or at the end
                        log_event("Server received 'end_of_transfer' signal in data. Breaking receive loop.")
                        break
                elif conn.state == "CLOSED": # Check if connection state indicates closure
                    log_event("Connection closed by peer during receive.")
                    break
                else:
                    # No data immediately available, sleep a bit to prevent busy-waiting
                    time.sleep(0.01) 
            except Exception as e:
                log_event(f"Server receive error: {e}")
                break
        
        log_event(f"Server finished receiving. Total bytes: {total_received_bytes}")
        log_event(f"Decoded message from client (may be truncated): {received_data.decode('utf-8', errors='ignore')[:200]}...") # Show first 200 chars

        # Simulate sending a response
        response_message = b"Server says: Your data was received! Great job! " \
                           b"This is a longer response to test data transfer back. " \
                           b"Hopefully, it also segments correctly and gets ACKed. " \
                           b"End of server response."
        
        log_event(f"Server preparing to send {len(response_message)} bytes response.")
        conn.send(response_message)
        log_event(f"Server finished queuing response data.")
        
        # Give some time for the response to be sent and acknowledged
        time.sleep(5) 

    except ConnectionRefusedError as e:
        log_event(f"Server connection error: {e}")
    except KeyboardInterrupt:
        log_event("Server shutting down due to user interrupt.")
    except Exception as e:
        log_event(f"An unexpected error occurred in server: {e}")
    finally:
        if server_socket:
            server_socket.close() # Ensure socket is closed on exit [cite: 66, 69]
        log_event("Server stopped.")

if __name__ == "__main__":
    run_server()
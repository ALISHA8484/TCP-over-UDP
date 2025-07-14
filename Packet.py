import socket
import struct
import random
import time
from datetime import datetime

MSS = 1024 # bytes 

# --- Packet Class ---
class Packet:
    """
    Represents a simplified TCP-like packet over UDP.
    Fields include: Source Port, Destination Port, Sequence Number,
    Acknowledgment Number, Control Flags (SYN, ACK, FIN, RST),
    Window Size (for Flow Control - initially fixed, then variable),
    Payload Length, and Data Payload.
    """
    # Define control flags as constants
    SYN = 0x01
    ACK = 0x02
    FIN = 0x04
    RST = 0x08

    HEADER_FORMAT = '!HHIIHH' # !: network byte order, H: unsigned short (2 bytes), I: unsigned int (4 bytes)
                               # Source Port (H), Dest Port (H), Seq Num (I), Ack Num (I), Flags/Window (H), Payload Length (H)
                               # Total header size: 2+2+4+4+2+2 = 16 bytes (we'll combine flags and window for simplicity or add window later)

    def __init__(self, src_port, dest_port, seq_num, ack_num, flags, window_size=128, payload=b''):
        self.src_port = src_port 
        self.dest_port = dest_port 
        self.seq_num = seq_num 
        self.ack_num = ack_num 
        self.flags = flags # SYN, ACK, FIN, RST 
        self.window_size = window_size # For flow control 
        self.payload = payload
        self.payload_length = len(payload)

    def to_bytes(self):
        """
        Converts the packet object into a byte string for transmission over UDP.
        The flags and window_size can be combined into a single 16-bit field,
        e.g., higher bits for flags and lower bits for window size, or simply add window_size as a separate field later.
        For simplicity, let's include flags and window size directly in the header format.
        Let's allocate a byte for flags and a short for window_size.
        Re-evaluating HEADER_FORMAT: src_port, dest_port, seq_num, ack_num, flags, window_size, payload_length
        """

        HEADER_FORMAT_ACTUAL = '!HHIIBHH'
        
        header = struct.pack(
            HEADER_FORMAT_ACTUAL,
            self.src_port,
            self.dest_port,
            self.seq_num,
            self.ack_num,
            self.flags,
            self.window_size,
            self.payload_length
        )
        return header + self.payload

    @classmethod
    def from_bytes(cls, data):
        """
        Reconstructs a Packet object from a byte string received over UDP.
        """
        HEADER_FORMAT_ACTUAL = '!HHIIBHH'
        HEADER_SIZE = struct.calcsize(HEADER_FORMAT_ACTUAL)

        if len(data) < HEADER_SIZE:
            raise ValueError("Received data is too short to be a valid packet header.")

        header = data[:HEADER_SIZE]
        payload = data[HEADER_SIZE:]

        src_port, dest_port, seq_num, ack_num, flags, window_size, payload_length = struct.unpack(HEADER_FORMAT_ACTUAL, header)

        # Basic check for payload length consistency, though UDP might truncate
        if len(payload) != payload_length:
            print(f"Warning: Payload length mismatch. Expected {payload_length}, got {len(payload)}")

        return cls(src_port, dest_port, seq_num, ack_num, flags, window_size, payload)

    def is_syn(self):
        return bool(self.flags & self.SYN)

    def is_ack(self):
        return bool(self.flags & self.ACK)

    def is_fin(self):
        return bool(self.flags & self.FIN)

    def is_rst(self):
        return bool(self.flags & self.RST)

    def __str__(self):
        flags_str = []
        if self.is_syn(): flags_str.append("SYN")
        if self.is_ack(): flags_str.append("ACK")
        if self.is_fin(): flags_str.append("FIN")
        if self.is_rst(): flags_str.append("RST")
        
        return (f"Packet(Src={self.src_port}, Dst={self.dest_port}, "
                f"Seq={self.seq_num}, Ack={self.ack_num}, "
                f"Flags={'|'.join(flags_str) if flags_str else 'NONE'}, "
                f"Window={self.window_size}, PayloadLen={self.payload_length})")

# --- Logging Helper (for scoring item 1) ---
def log_event(message):
    """Logs an event with a timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"[{timestamp}] {message}") #
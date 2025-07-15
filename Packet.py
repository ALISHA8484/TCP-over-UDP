import socket
import struct
import random
import time
from datetime import datetime

MSS = 1024 # bytes 

# --- Packet Class ---
class Packet:
    SYN = 0x01
    ACK = 0x02
    FIN = 0x04
    RST = 0x08
    HEADER_FORMAT_ACTUAL = '!HHIIBHH' # Source Port, Dest Port, Seq Num, Ack Num, Flags, Window Size, Payload Length

    def __init__(self, src_port, dest_port, seq_num, ack_num, flags, window_size=128, payload=b''):
        self.src_port = src_port
        self.dest_port = dest_port
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.flags = flags
        self.window_size = window_size
        self.payload = payload
        self.payload_length = len(payload)

    def to_bytes(self):
        header = struct.pack(
            self.HEADER_FORMAT_ACTUAL,
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
        HEADER_SIZE = struct.calcsize(cls.HEADER_FORMAT_ACTUAL)
        if len(data) < HEADER_SIZE:
            raise ValueError("Received data is too short to be a valid packet header.")
        header = data[:HEADER_SIZE]
        payload = data[HEADER_SIZE:]
        src_port, dest_port, seq_num, ack_num, flags, window_size, payload_length = struct.unpack(cls.HEADER_FORMAT_ACTUAL, header)
        if len(payload) != payload_length:
            log_event(f"Warning: Payload length mismatch. Expected {payload_length}, got {len(payload)}")
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
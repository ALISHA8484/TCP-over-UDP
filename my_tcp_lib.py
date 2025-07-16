import socket
import struct
import random
import time
import queue
import threading
from datetime import datetime

# تعریف حداکثر اندازه سگمنت (Maximum Segment Size)
MSS = 128 # بایت

# --- تابع کمکی برای لاگ کردن رویدادها ---
def log_event(message):
    """رویدادها را با timestamp لاگ می‌کند."""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"[{current_time}] {message}")

# --- کلاس Packet ---
class Packet:
    SYN = 0x01
    ACK = 0x02
    FIN = 0x04
    RST = 0x08
    # فرمت هدر بسته: پورت مبدا، پورت مقصد، شماره توالی، شماره تایید، فلگ‌ها، اندازه پنجره، طول پیلود
    HEADER_FORMAT = '!HHIIBHH' 

    def __init__(self, source_port, dest_port, seq_num, ack_num, flags, window_size=128, payload=b''):
        self.source_port = source_port
        self.dest_port = dest_port
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.flags = flags
        self.window_size = window_size
        self.payload = payload
        self.payload_length = len(payload)

    def to_bytes(self):
        header = struct.pack(
            self.HEADER_FORMAT,
            self.source_port,
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
        header_size = struct.calcsize(cls.HEADER_FORMAT)
        if len(data) < header_size:
            raise ValueError("Received data is too short to be a valid packet header.")
        header = data[:header_size]
        payload = data[header_size:]
        source_port, dest_port, seq_num, ack_num, flags, window_size, payload_length_from_packet = struct.unpack(cls.HEADER_FORMAT, header)
        if len(payload) != payload_length_from_packet:
            log_event(f"Warning: Payload length mismatch. Expected {payload_length_from_packet}, got {len(payload)} bytes.")
        return cls(source_port, dest_port, seq_num, ack_num, flags, window_size, payload)

    def is_syn(self):
        return bool(self.flags & self.SYN)
    def is_ack(self):
        return bool(self.flags & self.ACK)
    def is_fin(self):
        return bool(self.flags & self.FIN)
    def is_rst(self):
        return bool(self.flags & self.RST)

    def __str__(self):
        flags_text = []
        if self.is_syn(): flags_text.append("SYN")
        if self.is_ack(): flags_text.append("ACK")
        if self.is_fin(): flags_text.append("FIN")
        if self.is_rst(): flags_text.append("RST")
        return (f"Packet(Src={self.source_port}, Dst={self.dest_port}, "
                f"Seq={self.seq_num}, Ack={self.ack_num}, "
                f"Flags={'|'.join(flags_text) if flags_text else 'NONE'}, "
                f"Window={self.window_size}, PayloadLen={self.payload_length})")


# --- کلاس Connection ---
class Connection:
    def __init__(self, udp_socket, remote_address, is_server=False, scenario_flags=None):
        self.udp_socket = udp_socket
        self.remote_address = remote_address
        self.is_server = is_server

        self.state = "CLOSED"
        
        # شماره توالی اولیه (Initial Sequence Number)
        # برای آزمایش‌های ثابت، می‌توان آن را روی عدد ثابت (مثلاً 1) تنظیم کرد.
        self.initial_seq_num = 1 
        self.my_seq_num = self.initial_seq_num
        self.last_acked_seq_by_me = self.initial_seq_num

        self.peer_initial_seq_num = 0
        self.peer_ack_num = 0 # آخرین شماره تایید دریافت شده از مقصد
        self.next_expected_seq_from_peer = 0 # شماره توالی مورد انتظار بعدی از سمت مقابل

        self.send_buffer = b"" 
        self.receive_buffer = b"" 
        
        self.send_window_size = 65535
        self.receive_window_size = 65535
        
        # بسته‌های ارسال شده اما تایید نشده: {شماره_توالی: (بسته, زمان_ارسال)}
        self.unacked_sent_packets = {} 
        
        # مقدار پنجره‌ای که مقصد تبلیغ کرده (Receive Window)
        self.rwnd = self.receive_window_size 
        # پنجره کنترل ازدحام (Congestion Window)
        self.cwnd = MSS 
        # پنجره ارسال موثر (Effective Send Window): min(اندازه_پنجره_ارسال_برنامه, rwnd, cwnd)
        self.effective_send_window = min(self.send_window_size, self.rwnd, self.cwnd)
        
        self.duplicate_ack_count = 0 # شمارنده ACK تکراری
        # شماره توالی بسته‌ای که برای Fast Retransmit هدف قرار گرفته است.
        self.fast_retransmit_target_seq = None 

        self.retransmission_timeout = 1.0 # (Retransmission Timeout (RTO
        self.retransmission_timer = None 
        self.keep_alive_timer = None
        self.connection_timeout = 60

        self.incoming_packet_queue = queue.Queue() 
        self.out_of_order_receive_buffer = {} # Stores out-of-order packets: {seq_num: (packet_data, original_packet_obj)}

        # --- Scenario Flags Initialization ---
        scenario_flags = scenario_flags if scenario_flags is not None else {}
        self.SCENARIO_1_ACTIVE = scenario_flags.get('SCENARIO_1_ACTIVE', False)
        self.SCENARIO_2_ACTIVE = scenario_flags.get('SCARIO_2_ACTIVE', False)
        self.SCENARIO_3_ACTIVE = scenario_flags.get('SCENARIO_3_FAST_RETRANSMIT_ACTIVE', False)
        self.SCENARIO_4_ACTIVE = scenario_flags.get('SCENARIO_4_REORDER_ACTIVE', False)
        self.SCENARIO_5_ACTIVE = scenario_flags.get('SCENARIO_5_DUP_DATA_RECV_ACTIVE', False)

        self.packet_num = 0
        
        # شماره توالی بسته‌ای که یک بار برای سناریو 1 شبیه‌سازی شده که گم شده است.
        self.scenario1_lost_packet_seq = None 
        # شماره توالی ACK که یک بار برای سناریو 5 شبیه‌سازی شده که گم شده است.
        self.scenario5_lost_ack_seq = None
        # --- End Scenario Flags Initialization ---

        self.send_thread = threading.Thread(target=self._send_loop)
        self.receive_thread = threading.Thread(target=self._receive_loop) 
        self.is_running = False

    def _start_connection_threads(self):
        if not self.is_running:
            self.is_running = True
            self.send_thread.daemon = True
            self.receive_thread.daemon = True
            self.send_thread.start()
            self.receive_thread.start()
            log_event(f"Connection Threads Started for {self.remote_address}.")

    def _stop_connection_threads(self):
        if self.is_running:
            self.is_running = False
            log_event(f"Connection Threads Stoped for {self.remote_address}.")
            while not self.incoming_packet_queue.empty():
                try:
                    self.incoming_packet_queue.get_nowait()
                except queue.Empty:
                    break


    def _send_loop(self):
        while self.is_running:
            # محاسبه بایت‌های در پرواز
            bytes_in_flight = self.my_seq_num - self.last_acked_seq_by_me

            # لاگ وضعیت فعلی حلقه ارسال
            """
            log_event(f"Send loop state: MySeq={self.my_seq_num}, Acked={self.last_acked_seq_by_me}, "
                      f"InFlight={bytes_in_flight}, SendBufferLen={len(self.send_buffer)}, "
                      f"Window={self.effective_send_window}")
            """

            available_window_space = self.effective_send_window - bytes_in_flight
            
            # تعیین طول داده برای ارسال در این مرحله (min از بافر، پنجره، MSS)
            send_data_length = min(len(self.send_buffer), available_window_space, MSS)
            
            if send_data_length > 0:
                data_for_packet = self.send_buffer[:send_data_length] 
                packet_seq_num_for_this_send = self.my_seq_num # شماره توالی فعلی برای بسته جدید
                self.packet_num += 1
                # --- شبیه‌سازی Loss بسته داده اولیه برای سناریو ۱ (ACK تجمیعی و Fast Retransmit) ---
                # این شبیه‌سازی تلاش اولیه ارسال یک بسته را حذف می‌کند.
                do_physical_send = True # پرچم کنترل ارسال فیزیکی در این تلاش
                if self.SCENARIO_1_ACTIVE and \
                   self.scenario1_lost_packet_seq is None and \
                   self.packet_num == 4 : # هدف قرار دادن اولین بسته داده پس از Handshake
                    
                    log_event(f"SIMULATING LOSS (Scenario 1): Dropping actual UDP transmission for packet {self.packet_num} - Seq={packet_seq_num_for_this_send}.")
                    self.scenario1_lost_packet_seq = packet_seq_num_for_this_send # علامت‌گذاری بسته به عنوان "یک بار از دست رفته"
                    self.SCENARIO_1_ACTIVE = False # اطمینان از اینکه فقط یک بار این حذف انجام شود.
                    do_physical_send = False # جلوگیری از فراخوانی udp_socket.sendto() در این تلاش

                # ساخت بسته برای ارسال (چه به صورت واقعی و چه برای ردیابی در unacked_sent_packets)
                packet_to_send = Packet(self.udp_socket.getsockname()[1], self.remote_address[1], 
                                packet_seq_num_for_this_send, self.next_expected_seq_from_peer, Packet.ACK, # ACK flag for data packets
                                self.receive_window_size, data_for_packet)
                
                # اضافه کردن به بسته‌های تایید نشده و پیشروی شماره توالی
                # این کار باید همیشه (در صورت ارسال مفهومی) انجام شود تا بسته در InFlight باشد و تایمرش شروع شود.
                self.unacked_sent_packets[packet_to_send.seq_num] = (packet_to_send, time.time())
                
                # پیشروی my_seq_num و کوتاه کردن send_buffer (فقط یک بار برای هر ارسال مفهومی)
                self.my_seq_num += len(data_for_packet) 
                self.send_buffer = self.send_buffer[send_data_length:] # داده از بافر ارسال مصرف شد.

                if do_physical_send: # اگر برای حذف علامت‌گذاری نشده بود، ارسال فیزیکی کن.
                    try:
                        self.udp_socket.sendto(packet_to_send.to_bytes(), self.remote_address)
                        log_event(f"Sent packet {self.packet_num} : Seq={packet_to_send.seq_num}, Len={len(data_for_packet)}, InFlight={bytes_in_flight + len(data_for_packet)}.")
                        
                    except Exception as e:
                        log_event(f"Send error for Seq={packet_to_send.seq_num}: {e}.")
                else: # اگر برای حذف علامت‌گذاری شده بود، فقط لاگ مربوطه را بزن.
                    log_event(f"Physical send skipped for Seq={packet_to_send.seq_num} (simulated loss).")
                
                time.sleep(0.05) # مکث کوتاه پس از هر تلاش ارسال برای مشاهده بهتر

            # مدیریت بازارسال برای بسته‌هایی که ارسال شده اما هنوز تایید نشده‌اند.
            current_time = time.time()
            for seq, (unacked_packet, send_time) in list(self.unacked_sent_packets.items()):
                if current_time - send_time > self.retransmission_timeout:
                    log_event(f"Retransmitting packet Seq={unacked_packet.seq_num} due to timeout.")
                    try:
                        self.udp_socket.sendto(unacked_packet.to_bytes(), self.remote_address)
                        self.unacked_sent_packets[seq] = (unacked_packet, current_time) # به‌روزرسانی زمان ارسال برای تلاش بازارسال بعدی
                        
                        self.cwnd = MSS # تنظیم مجدد CWND به MSS پس از Timeout
                        log_event(f"CWND reset to {self.cwnd} due to timeout.")
                        self.effective_send_window = min(self.send_window_size, self.rwnd, self.cwnd)
                        self.duplicate_ack_count = 0 # بازنشانی شمارنده ACK تکراری
                        self.fast_retransmit_target_seq = None # پاک کردن هدف Fast Retransmit

                    except Exception as e:
                        log_event(f"Retransmission error for packet Seq={unacked_packet.seq_num}: {e}.")

            time.sleep(0.01) # مکث کوتاه حلقه

    def _receive_loop(self):
        while self.is_running:
            try:
                packet_received = self.incoming_packet_queue.get(timeout=0.1) # گرفتن بسته از صف (با تایم‌اوت)
                
                # --- شبیه‌سازی Loss برای ACK در سناریو ۵ (دریافت داده تکراری) ---
                # این شبیه‌سازی روی ACK های ورودی (در سمت کلاینت) اعمال می‌شود.
                # مثال: گم کردن ACK برای بسته با شماره توالی اولیه + 5 * MSS + 1 (تقریباً بسته ششم داده)
                if self.SCENARIO_5_ACTIVE and packet_received.is_ack() and \
                   self.scenario5_lost_ack_seq is None and \
                   packet_received.ack_num == (self.initial_seq_num + MSS * 5 + 1): 
                    
                    log_event(f"SIMULATING LOSS: Dropping ACK for Ack={packet_received.ack_num} for Scenario 5.")
                    self.scenario5_lost_ack_seq = packet_received.ack_num # علامت‌گذاری ACK از دست رفته
                    self.SCENARIO_5_ACTIVE = False # اطمینان از اینکه فقط یک بار ACK حذف شود.
                    continue # از پردازش این ACK صرف‌نظر می‌کنیم
                # --- پایان شبیه‌سازی ---

                self._handle_incoming_packet(packet_received) # پردازش بسته
                time.sleep(0.02) # مکث کوتاه پس از پردازش هر بسته
            except queue.Empty:
                pass # صف خالی است، ادامه حلقه
            except Exception as e:
                log_event(f"Receive loop error: {e}.") 

    def _handle_incoming_packet(self, packet):
        log_event(f"Received packet for {self.remote_address}: {packet}")

        if packet.is_rst():
            log_event(f"Received RST from {self.remote_address}. Connection reset.")
            self.state = "CLOSED"
            self._stop_connection_threads()
            return

        # --- پردازش سگمنت ACK ---
        if packet.is_ack():
            # بررسی می‌کنیم که آیا این ACK، پنجره ارسال ما را پیش می‌برد (یعنی داده‌های جدیدی را تایید می‌کند).
            if packet.ack_num > self.last_acked_seq_by_me:
                log_event(f"ACK received: Ack={packet.ack_num}, PrevAcked={self.last_acked_seq_by_me}. Moving send window.")
                
                newly_acked_bytes = packet.ack_num - self.last_acked_seq_by_me
                
                if newly_acked_bytes > 0:
                    # بافر ارسال را فقط در صورت تایید شدن بایت‌های جدید، کوتاه می‌کنیم.
                    self.send_buffer = self.send_buffer[newly_acked_bytes:]
                    log_event(f"Removed {newly_acked_bytes} bytes from send buffer. Remaining: {len(self.send_buffer)}.")

                self.last_acked_seq_by_me = packet.ack_num 
                
                # بسته‌هایی که با این ACK جدید تایید شده‌اند را از لیست بسته‌های تایید نشده حذف می‌کنیم.
                keys_to_remove = []
                for seq_num, (sent_packet, send_time) in list(self.unacked_sent_packets.items()):
                    if (sent_packet.seq_num + sent_packet.payload_length) <= packet.ack_num: 
                        keys_to_remove.append(seq_num)
                for key in keys_to_remove:
                    del self.unacked_sent_packets[key]
                
                self.cwnd += MSS # افزایش CWND بر اساس قانون کنترل ازدحام (افزایش خطی)
                log_event(f"CWND increased to {self.cwnd} due to new ACK.")
                self.effective_send_window = min(self.send_window_size, self.rwnd, self.cwnd)

                self.duplicate_ack_count = 0 # بازنشانی شمارنده ACK تکراری پس از دریافت ACK جدید
                self.fast_retransmit_target_seq = None # پاک کردن هدف Fast Retransmit

            else: # packet.ack_num <= self.last_acked_seq_by_me (این یک ACK تکراری است)
                log_event(f"Received duplicate ACK: Ack={packet.ack_num}, CurrentAcked={self.last_acked_seq_by_me}.")
                self.duplicate_ack_count += 1
                
                if self.duplicate_ack_count == 1: # اولین ACK تکراری، هدف Fast Retransmit را مشخص می‌کند.
                    # هدف Fast Retransmit، کوچکترین شماره توالی بسته‌ای است که فرستنده ارسال کرده اما هنوز تایید نشده است.
                    if self.unacked_sent_packets:
                        self.fast_retransmit_target_seq = min(self.unacked_sent_packets.keys()) 
                    log_event(f"First duplicate ACK. Target for Fast Retransmit: {self.fast_retransmit_target_seq}.")

                if self.duplicate_ack_count >= 3: # آستانه 3 ACK تکراری برای Fast Retransmit
                    # فقط در صورتی بازارسال می‌کنیم که بسته هدف واقعاً در صف بسته‌های تایید نشده ما باشد.
                    if self.fast_retransmit_target_seq is not None and self.fast_retransmit_target_seq in self.unacked_sent_packets:
                        log_event(f"3 Duplicate ACKs received. Performing Fast Retransmit for Seq={self.fast_retransmit_target_seq}.")
                        
                        packet_to_retransmit, _ = self.unacked_sent_packets[self.fast_retransmit_target_seq]
                        try:
                            self.udp_socket.sendto(packet_to_retransmit.to_bytes(), self.remote_address)
                            
                            self.cwnd = max(MSS, self.cwnd // 2) # نصف کردن CWND (کنترل ازدحام)
                            log_event(f"CWND halved to {self.cwnd} due to 3 duplicate ACKs.")
                            self.effective_send_window = min(self.send_window_size, self.rwnd, self.cwnd)
                            
                            self.duplicate_ack_count = 0 # بازنشانی شمارنده ACK تکراری پس از بازارسال سریع
                            self.fast_retransmit_target_seq = None
                            
                        except Exception as e:
                            log_event(f"Error during Fast Retransmit for Seq={packet_to_retransmit.seq_num}: {e}.")
                    else:
                        log_event("Fast Retransmit triggered but target packet not found or already retransmitted/acked.")

            self.rwnd = packet.window_size # همیشه پنجره دریافت تبلیغ شده توسط مقصد را به‌روزرسانی می‌کنیم.
            self.effective_send_window = min(self.send_window_size, self.rwnd, self.cwnd)

        # --- پردازش پیلود داده ---
        if packet.payload_length > 0:
            log_event(f"Processing data: Seq={packet.seq_num}, Expected={self.next_expected_seq_from_peer}, Len={packet.payload_length}.")
            
            if packet.seq_num == self.next_expected_seq_from_peer:
                self.receive_buffer += packet.payload
                self.next_expected_seq_from_peer += packet.payload_length 
                log_event(f"Received in-order data. New next_expected_seq: {self.next_expected_seq_from_peer}.")
                
                # تحویل بسته‌های خارج از ترتیب بافر شده که اکنون به ترتیب آمده‌اند
                while self.next_expected_seq_from_peer in self.out_of_order_receive_buffer:
                    buffered_packet = self.out_of_order_receive_buffer.pop(self.next_expected_seq_from_peer)
                    self.receive_buffer += buffered_packet.payload
                    self.next_expected_seq_from_peer += buffered_packet.payload_length
                    log_event(f"Delivered buffered packet Seq={buffered_packet.seq_num}. New next_expected_seq: {self.next_expected_seq_from_peer}.")
                
                # ارسال ACK تجمیعی برای داده‌های جدید پیوسته
                ack_packet = Packet(self.udp_socket.getsockname()[1], self.remote_address[1],
                                    self.my_seq_num, self.next_expected_seq_from_peer, Packet.ACK,
                                    self.receive_window_size) 
                try:
                    self.udp_socket.sendto(ack_packet.to_bytes(), self.remote_address)
                    log_event(f"Sent ACK for data: Ack={ack_packet.ack_num}, Window={ack_packet.window_size}.")
                except Exception as e:
                    log_event(f"Error sending ACK for data: {e}.")

            elif packet.seq_num > self.next_expected_seq_from_peer: # بسته خارج از ترتیب است.
                log_event(f"Received out-of-order packet: Expected={self.next_expected_seq_from_peer}, Got={packet.seq_num}. Buffering.")
                if packet.seq_num not in self.out_of_order_receive_buffer: # جلوگیری از افزودن تکراری به بافر
                    self.out_of_order_receive_buffer[packet.seq_num] = packet
                # ارسال ACK تکراری برای آخرین بایت صحیح دریافت شده (next_expected_seq_from_peer)
                ack_packet = Packet(self.udp_socket.getsockname()[1], self.remote_address[1],
                                    self.my_seq_num, self.next_expected_seq_from_peer, Packet.ACK,
                                    self.receive_window_size)
                try:
                    self.udp_socket.sendto(ack_packet.to_bytes(), self.remote_address)
                    log_event(f"Sent Duplicate ACK for out-of-order: Ack={ack_packet.ack_num}, Window={ack_packet.window_size}.")
                except Exception as e:
                    log_event(f"Error sending Duplicate ACK: {e}.")
            else: # بسته با شماره توالی کمتر از next_expected_seq_from_peer (تکراری یا قبلاً پردازش شده)
                log_event(f"Received old/duplicate data: Seq={packet.seq_num}, Expected={self.next_expected_seq_from_peer}. Discarding.")
                # همیشه یک ACK برای داده‌های قدیمی/تکراری ارسال کنید تا به فرستنده کمک کند.
                ack_packet = Packet(self.udp_socket.getsockname()[1], self.remote_address[1],
                                    self.my_seq_num, self.next_expected_seq_from_peer, Packet.ACK,
                                    self.receive_window_size)
                try:
                    self.udp_socket.sendto(ack_packet.to_bytes(), self.remote_address)
                    log_event(f"Sent Duplicate ACK for old data: Ack={ack_packet.ack_num}, Window={ack_packet.window_size}.")
                except Exception as e:
                    log_event(f"Error sending Duplicate ACK for old data: {e}.")

            #time.sleep(2)
            

        # --- مدیریت فلگ FIN ---
        if packet.is_fin():
            log_event(f"Received FIN from {self.remote_address}. Initiating close process.")
            if self.state == "ESTABLISHED": 
                self.state = "CLOSE_WAIT" 
                fin_ack_packet = Packet(self.udp_socket.getsockname()[1], self.remote_address[1],
                                            self.my_seq_num, packet.seq_num + 1, Packet.ACK,
                                            self.receive_window_size)
                try:
                    self.udp_socket.sendto(fin_ack_packet.to_bytes(), self.remote_address)
                    log_event(f"Sent ACK to FIN from {self.remote_address}.")
                    if not self.send_buffer and not self.unacked_sent_packets: 
                        self.close() 
                except Exception as e:
                    log_event(f"Error sending ACK for FIN: {e}.")
            elif self.state == "FIN_WAIT_2": 
                log_event(f"Received FIN from {self.remote_address} while in FIN_WAIT_2. Moving to TIME_WAIT.")
                self.state = "TIME_WAIT"
                final_fin_ack_packet = Packet(self.udp_socket.getsockname()[1], self.remote_address[1],
                                            self.my_seq_num, packet.seq_num + 1, Packet.ACK,
                                            self.receive_window_size)
                try:
                    self.udp_socket.sendto(final_fin_ack_packet.to_bytes(), self.remote_address)
                    log_event(f"Sent final ACK to {self.remote_address} for their FIN. Entering TIME_WAIT.")
                except Exception as e:
                    log_event(f"Error sending final ACK for FIN: {e}.")
                threading.Timer(2 * self.retransmission_timeout, self._close_after_time_wait).start()

        if self.state == "FIN_WAIT_1" and packet.is_ack() and packet.ack_num == (self.my_seq_num): # ACK for our FIN
            log_event(f"Received ACK for our FIN from {self.remote_address}. Moving to FIN_WAIT_2.")
            self.state = "FIN_WAIT_2"


    def send(self, data):
        log_event(f"Application requested to send {len(data)} bytes to {self.remote_address}.")
        self.send_buffer += data

    def receive(self, buffer_size):
        log_event(f"Application requested to receive {buffer_size} bytes from {self.remote_address}.")
        
        while len(self.receive_buffer) < buffer_size:
            if not self.is_running and len(self.receive_buffer) == 0:
                log_event(f"Connection with {self.remote_address} is closed and no data in buffer.")
                return b''
            time.sleep(0.01) 
        
        read_data = self.receive_buffer[:buffer_size]
        self.receive_buffer = self.receive_buffer[buffer_size:]
        
        log_event(f"Application received {len(read_data)} bytes from {self.remote_address}.")
        return read_data

    def close(self):
        log_event(f"Initiating connection close for {self.remote_address}.")
        if self.state == "ESTABLISHED" or self.state == "CLOSE_WAIT": 
            if self.state == "ESTABLISHED": 
                self.state = "FIN_WAIT_1"
                fin_packet = Packet(self.udp_socket.getsockname()[1], self.remote_address[1],
                                    self.my_seq_num, self.next_expected_seq_from_peer, Packet.FIN,
                                    self.receive_window_size)
                try:
                    self.udp_socket.sendto(fin_packet.to_bytes(), self.remote_address)
                    log_event(f"Sent FIN to {self.remote_address}. Seq={fin_packet.seq_num}.")
                    self.my_seq_num += 1 
                except Exception as e:
                    log_event(f"Error sending FIN: {e}.")


    def _close_after_time_wait(self):
        log_event(f"Exiting TIME_WAIT state for {self.remote_address}. Connection fully closed.")
        self.state = "CLOSED"
        self._stop_connection_threads() 


# --- کلاس TCPSocket ---
class TCPSocket:
    def __init__(self):
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow address reuse
        self.udp_socket.setblocking(False) 
        self.is_listening_socket = False
        self.accept_queue = queue.Queue() # Queue for accepted connections
        self.active_connections = {} # {remote_address: Connection_object}
        self.listening_thread = None
        self.is_running = False

    def bind(self, address):
        self.udp_socket.bind(address)
        log_event(f"Socket bound to {address}.")

    def listen(self, backlog_size): 
        self.is_listening_socket = True
        self.max_backlog_size = backlog_size
        log_event(f"Socket listening with backlog {backlog_size}.")
        self._start_listening_thread() 

    def _start_listening_thread(self):
        if not self.is_running:
            self.is_running = True
            self.listening_thread = threading.Thread(target=self._listen_loop)
            self.listening_thread.daemon = True
            self.listening_thread.start()
            log_event(f"Listening thread started on {self.udp_socket.getsockname()}.")


    def _listen_loop(self):
        while self.is_running:
            try:
                data, received_address = self.udp_socket.recvfrom(4096) 
                received_packet = Packet.from_bytes(data)
                log_event(f"Received UDP packet from {received_address}: {received_packet}")

                target_connection = None
                if received_address in self.active_connections:
                    target_connection = self.active_connections[received_address]
                
                if target_connection: # If packet is for an existing connection (or one in handshake)
                    # Logic for handling final ACK of 3-way handshake on server side
                    if target_connection.state == "SYN_RCVD" and received_packet.is_ack() and \
                       received_packet.ack_num == (target_connection.initial_seq_num + 1) and \
                       received_packet.seq_num == (target_connection.peer_initial_seq_num + 1):
                        
                        log_event(f"Received final ACK from {received_address}. Connection ESTABLISHED.")
                        
                        target_connection.my_seq_num = target_connection.initial_seq_num + 1 
                        target_connection.last_acked_seq_by_me = received_packet.ack_num 

                        log_event(f"Server updated MySeq={target_connection.my_seq_num} and LastAcked={target_connection.last_acked_seq_by_me} after final ACK.")

                        target_connection.state = "ESTABLISHED"
                        target_connection._start_connection_threads()
                        self.accept_queue.put((target_connection, received_address)) # Make it available to the application via accept()
                    else:
                        # For ALL other packets belonging to this active connection (data, FIN, RST, other ACKs)
                        # Pass them to the connection's handler via its internal queue.
                        log_event(f"Queuing packet for connection {received_address}, state: {target_connection.state}. Packet: {received_packet}")
                        target_connection.incoming_packet_queue.put(received_packet) 
                
                elif received_packet.is_syn() and self.is_listening_socket: # New SYN request (only if listening as server)
                    if self.accept_queue.qsize() < self.max_backlog_size:
                        log_event(f"Received SYN from {received_address}. Initiating 3-way handshake.")
                        # Server connection does not run client-side loss scenarios by default.
                        new_connection = Connection(self.udp_socket, received_address, is_server=True, scenario_flags=None) 
                        new_connection.peer_initial_seq_num = received_packet.seq_num 
                        new_connection.next_expected_seq_from_peer = received_packet.seq_num + 1 

                        syn_ack_packet = Packet(self.udp_socket.getsockname()[1], received_address[1],
                                                new_connection.initial_seq_num, new_connection.next_expected_seq_from_peer,
                                                Packet.SYN | Packet.ACK, new_connection.receive_window_size)
                        self.udp_socket.sendto(syn_ack_packet.to_bytes(), received_address)
                        log_event(f"Sent SYN-ACK to {received_address}. Seq={syn_ack_packet.seq_num}, Ack={syn_ack_packet.ack_num}.")
                        
                        self.active_connections[received_address] = new_connection 
                        new_connection.state = "SYN_RCVD" 
                    else:
                        log_event(f"SYN from {received_address} rejected: backlog full.")
                        rst_packet = Packet(self.udp_socket.getsockname()[1], received_address[1], 0, 0, Packet.RST)
                        self.udp_socket.sendto(rst_packet.to_bytes(), received_address)
                
                else: # Unrecognized/invalid packet (not for active conn, not a new SYN)
                    log_event(f"Received unrecognized/invalid packet from {received_address}: {received_packet}. Sending RST.")
                    rst_packet = Packet(self.udp_socket.getsockname()[1], received_address[1], 0, 0, Packet.RST)
                    self.udp_socket.sendto(rst_packet.to_bytes(), received_address)

            except socket.error as e:
                # 10035 is WSAEWOULDBLOCK on Windows, means no data. Expected for non-blocking.
                if e.errno == 10035: 
                    pass 
                else:
                    log_event(f"Socket error in listen loop: {e}.")
            except ValueError as e:
                log_event(f"Packet parsing error: {e}. Data: {data[:50] if 'data' in locals() else 'N/A'}.") 
            except Exception as e:
                log_event(f"Unexpected error in listen loop: {e}.")
            time.sleep(0.001) 

    def accept(self): 
        log_event("Waiting for incoming connection (blocking on accept).")
        connection_object, address = self.accept_queue.get() 
        log_event(f"Accepted connection from {address}.")
        return connection_object, address

    def connect(self, remote_address): 
        log_event(f"Attempting to connect to {remote_address}...")
        
        # پورت مبدأ کلاینت به صورت تصادفی توسط سیستم‌عامل انتخاب می‌شود (پورت 0)
        # برای پورت‌های غیر شناخته شده (>1024) می‌توان random.randint(1025, 65535) انتخاب و bind کرد.
        self.udp_socket.bind(('0.0.0.0', 0)) 
        log_event(f"Client socket bound to {self.udp_socket.getsockname()}.")
        
        # پرچم‌های سناریو برای Connection کلاینت
        client_scenario_flags = {
            'SCENARIO_1_ACTIVE': True, # فعال کردن سناریو 1 (Loss بسته داده اولیه)
            'SCENARIO_2_ACTIVE': False, # سناریو 2 (Loss و بازارسال با Timeout)
            'SCENARIO_3_ACTIVE': True, # سناریو 3 (Fast Retransmit با 3 ACK تکراری)
            'SCENARIO_4_ACTIVE': True, # سناریو 4 (ترتیب دریافت نادرست بسته ها) - با سناریو 1 ترکیب می‌شود
            'SCENARIO_5_DUP_DATA_RECV_ACTIVE': True # سناریو 5 (دریافت داده تکراری به دلیل گم شدن ACK)
        }
        connection_obj = Connection(self.udp_socket, remote_address, scenario_flags=client_scenario_flags) 
        self.active_connections[remote_address] = connection_obj

        self._start_listening_thread() 

        # گام 1: ارسال SYN
        syn_packet = Packet(self.udp_socket.getsockname()[1], remote_address[1],
                            connection_obj.initial_seq_num, 0, Packet.SYN) 
        
        connection_obj.state = "SYN_SENT"
        retries_count = 5 
        retry_timeout_sec = 2 # ثانیه
        
        for i in range(retries_count):
            try:
                self.udp_socket.sendto(syn_packet.to_bytes(), remote_address)
                log_event(f"Sent SYN to {remote_address} (Attempt {i+1}). Seq={syn_packet.seq_num}.")

                start_wait_time = time.time()
                syn_ack_received_flag = False
                while time.time() - start_wait_time < retry_timeout_sec:
                    try:
                        received_response_packet = connection_obj.incoming_packet_queue.get(timeout=0.1) 
                        if received_response_packet.is_syn() and received_response_packet.is_ack() and received_response_packet.ack_num == (connection_obj.initial_seq_num + 1):
                            log_event(f"Received SYN-ACK from {remote_address}. Seq={received_response_packet.seq_num}, Ack={received_response_packet.ack_num}.")
                            syn_ack_received_flag = True
                            break
                        else:
                            log_event(f"Received unexpected packet during SYN_SENT state: {received_response_packet}. Discarding.")
                    except queue.Empty:
                        pass # صف خالی است، ادامه انتظار
                
                if syn_ack_received_flag:
                    connection_obj.peer_initial_seq_num = received_response_packet.seq_num
                    connection_obj.next_expected_seq_from_peer = received_response_packet.seq_num + 1 
                    
                    connection_obj.my_seq_num = connection_obj.initial_seq_num + 1 
                    connection_obj.last_acked_seq_by_me = received_response_packet.ack_num 

                    log_event(f"Client updated MySeq={connection_obj.my_seq_num} and LastAcked={connection_obj.last_acked_seq_by_me} after SYN-ACK.")
                    
                    connection_obj.state = "ESTABLISHED"

                    actual_client_source_port = self.udp_socket.getsockname()[1] 
                    ack_packet_final = Packet(actual_client_source_port, remote_address[1],
                                        connection_obj.my_seq_num, connection_obj.next_expected_seq_from_peer, Packet.ACK) 
                    self.udp_socket.sendto(ack_packet_final.to_bytes(), remote_address)
                    log_event(f"Sent final ACK to {remote_address}. Seq={ack_packet_final.seq_num}, Ack={ack_packet_final.ack_num}.")
                    
                    connection_obj._start_connection_threads() 
                    return connection_obj # اتصال با موفقیت برقرار شد.
                else: 
                    log_event(f"Did not receive expected SYN-ACK from {remote_address} within timeout.")

            except Exception as e:
                log_event(f"Error sending SYN or during handshake: {e}.")
            time.sleep(retry_timeout_sec) 

        log_event(f"Failed to connect to {remote_address} after {retries_count} retries. Connection aborted.")
        del self.active_connections[remote_address]
        raise ConnectionRefusedError(f"Could not connect to {remote_address}.")

    def close(self): 
        log_event("Closing main socket.")
        self.is_running = False 

        if self.listening_thread and self.listening_thread.is_alive():
            self.listening_thread.join(timeout=1) 

        for address, connection_obj in list(self.active_connections.items()):
            log_event(f"Initiating close for active connection {address} (during main socket close).")
            connection_obj.close() # شروع Handshake FIN برای هر اتصال فعال
        
        while not self.accept_queue.empty():
            conn_in_queue, _ = self.accept_queue.get_nowait()
            log_event(f"Closing pending connection in accept queue.")
            conn_in_queue._stop_connection_threads()

        self.udp_socket.close()
        log_event("Main socket closed.")
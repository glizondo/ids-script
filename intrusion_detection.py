import socket
import struct
import time
import logging
import platform
from collections import defaultdict
import ctypes
import sys
import platform

PORT_SCAN_THRESHOLD = 5
TIME_WINDOW = 10
LOG_FILE = "intrusion_detector.log"

# Logging setup
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

scan_log_tcp = defaultdict(list)
scan_log_udp = defaultdict(list)

IS_WINDOWS = platform.system().lower() == "windows"


def is_admin():
    if platform.system().lower() == "windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        import os
        return os.geteuid() == 0


if not is_admin():
    print("[!] Please run this script as administrator (Windows) or root (Linux).")
    sys.exit(1)


def create_socket(protocol):
    if IS_WINDOWS:
        proto = socket.IPPROTO_IP
    else:
        proto = socket.IPPROTO_TCP if protocol == "TCP" else socket.IPPROTO_UDP

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if IS_WINDOWS:
        host_ip = socket.gethostbyname(socket.gethostname())
        s.bind((host_ip, 0))
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    return s


def get_packet(sock):
    packet, _ = sock.recvfrom(65565)
    return packet


def parse_ip_header(packet):
    iph = struct.unpack('!BBHHHBBH4s4s', packet[0:20])
    return socket.inet_ntoa(iph[8])


def parse_tcp_header(packet):
    if len(packet) < 40:
        raise ValueError("Packet too short for TCP header")
    tcp_header = packet[20:40]
    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
    src_port = tcph[0]
    dst_port = tcph[1]
    flags = tcph[5]
    return src_port, dst_port, flags

def parse_udp_header(packet):
    if len(packet) < 28:
        raise ValueError("Packet too short for UDP header")
    udp_header = packet[20:28]
    udph = struct.unpack('!HHHH', udp_header)
    src_port = udph[0]
    dst_port = udph[1]
    return src_port, dst_port


def detect_intrusions():
    print("[*] Intrusion Detection System running... Press Ctrl+C to stop.")
    tcp_socket = create_socket("TCP")
    udp_socket = create_socket("UDP")

    try:
        while True:
            for protocol, sock in [("TCP", tcp_socket), ("UDP", udp_socket)]:
                packet = get_packet(sock)
                current_time = time.time()

                try:
                    src_ip = parse_ip_header(packet)

                    if protocol == "TCP":
                        _, dst_port, flags = parse_tcp_header(packet)
                        if flags & 0x02:  # SYN flag
                            scan_log_tcp[src_ip].append((dst_port, current_time))
                            scan_log_tcp[src_ip] = [
                                (port, t) for port, t in scan_log_tcp[src_ip]
                                if current_time - t <= TIME_WINDOW
                            ]
                            if len(set(port for port, _ in scan_log_tcp[src_ip])) >= PORT_SCAN_THRESHOLD:
                                msg = f"TCP Port scan detected from {src_ip}. Ports: {[port for port, _ in scan_log_tcp[src_ip]]}"
                                print(f"[!] {msg}")
                                logging.warning(msg)

                    elif protocol == "UDP":
                        _, dst_port = parse_udp_header(packet)
                        scan_log_udp[src_ip].append((dst_port, current_time))
                        scan_log_udp[src_ip] = [
                            (port, t) for port, t in scan_log_udp[src_ip]
                            if current_time - t <= TIME_WINDOW
                        ]
                        if len(set(port for port, _ in scan_log_udp[src_ip])) >= PORT_SCAN_THRESHOLD:
                            msg = f"UDP Port scan detected from {src_ip}. Ports: {[port for port, _ in scan_log_udp[src_ip]]}"
                            print(f"[!] {msg}")
                            logging.warning(msg)

                except ValueError as ve:
                    logging.debug(f"Malformed packet skipped: {ve}")
                    continue

    except KeyboardInterrupt:
        print("\n[!] Stopping IDS.")
        logging.info("IDS stopped by user.")


if __name__ == '__main__':
    detect_intrusions()

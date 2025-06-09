import socket
import struct
import time
import logging
import platform
import ctypes
import sys
import json
import smtplib
from email.mime.text import MIMEText
from collections import defaultdict

# Configurable parameters
PORT_SCAN_THRESHOLD = 15
TIME_WINDOW = 10
LOG_FILE = "intrusion_detector.log"
WHITELIST_FILE = "whitelist.json"
CONFIG_FILE = "config.json"
COMMON_TCP_SCAN_PORTS = range(1, 1024)
COMMON_UDP_SCAN_PORTS = range(1, 1024)

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
    if IS_WINDOWS:
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


def load_whitelist():
    try:
        with open(WHITELIST_FILE, 'r') as f:
            data = json.load(f)
            return set(data.get("whitelisted_ips", []))
    except Exception as e:
        logging.error(f"Error loading whitelist: {e}")
        return set()


def load_config():
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f).get("email", {})
    except Exception as e:
        logging.error(f"Error loading config: {e}")
        return {}


WHITELISTED_IPS = load_whitelist()
EMAIL_CONFIG = load_config()


def send_email_alert(subject, body):
    if not EMAIL_CONFIG.get("enabled"):
        return

    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = EMAIL_CONFIG["sender_email"]
        msg["To"] = EMAIL_CONFIG["receiver_email"]

        with smtplib.SMTP(EMAIL_CONFIG["smtp_server"], EMAIL_CONFIG["smtp_port"]) as server:
            server.starttls()
            server.login(EMAIL_CONFIG["username"], EMAIL_CONFIG["password"])
            server.sendmail(
                EMAIL_CONFIG["sender_email"],
                EMAIL_CONFIG["receiver_email"],
                msg.as_string()
            )
        logging.info("Email alert sent.")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")


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
    tcph = struct.unpack('!HHLLBBHHH', packet[20:40])
    return tcph[0], tcph[1], tcph[5]


def parse_udp_header(packet):
    if len(packet) < 28:
        raise ValueError("Packet too short for UDP header")
    udph = struct.unpack('!HHHH', packet[20:28])
    return udph[0], udph[1]


def detect_intrusions():
    print("[*] Intrusion Detection System running... Press Ctrl+C to stop.")
    tcp_socket = create_socket("TCP")
    udp_socket = create_socket("UDP")

    try:
        while True:
            for protocol, sock in [("TCP", tcp_socket), ("UDP", udp_socket)]:
                try:
                    packet = get_packet(sock)
                    current_time = time.time()
                    src_ip = parse_ip_header(packet)

                    if src_ip in WHITELISTED_IPS:
                        continue

                    if protocol == "TCP":
                        _, dst_port, flags = parse_tcp_header(packet)
                        if flags & 0x02 and dst_port in COMMON_TCP_SCAN_PORTS:
                            scan_log_tcp[src_ip].append((dst_port, current_time))
                            scan_log_tcp[src_ip] = [
                                (port, t) for port, t in scan_log_tcp[src_ip]
                                if current_time - t <= TIME_WINDOW
                            ]
                            ports = set(port for port, _ in scan_log_tcp[src_ip])
                            if len(ports) >= PORT_SCAN_THRESHOLD:
                                msg = f"TCP Port scan detected from {src_ip}. Ports: {list(ports)}"
                                print(f"[!] {msg}")
                                logging.warning(msg)
                                send_email_alert("TCP Port Scan Detected", msg)

                    elif protocol == "UDP":
                        _, dst_port = parse_udp_header(packet)
                        if dst_port not in COMMON_UDP_SCAN_PORTS:
                            continue
                        scan_log_udp[src_ip].append((dst_port, current_time))
                        scan_log_udp[src_ip] = [
                            (port, t) for port, t in scan_log_udp[src_ip]
                            if current_time - t <= TIME_WINDOW
                        ]
                        ports = set(port for port, _ in scan_log_udp[src_ip])
                        if len(ports) >= PORT_SCAN_THRESHOLD:
                            msg = f"UDP Port scan detected from {src_ip}. Ports: {list(ports)}"
                            print(f"[!] {msg}")
                            logging.warning(msg)
                            send_email_alert("UDP Port Scan Detected", msg)

                except ValueError:
                    continue

    except KeyboardInterrupt:
        print("\n[!] Stopping IDS.")
        logging.info("IDS stopped by user.")


if __name__ == '__main__':
    detect_intrusions()

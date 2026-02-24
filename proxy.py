import socket
import struct
import base64
import os
import logging
import threading
import requests
import time

# --- LOGGING ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
logger = logging.getLogger("ProxyEngine")

# --- CONFIG ---
USER = "Arsen1k"
PASS = "Speed123"
AUTH_B64 = base64.b64encode(f"{USER}:{PASS}".encode()).decode()

TOKEN = os.environ.get("TELEGRAM_TOKEN")
OWNER_ID = os.environ.get("OWNER_ID")
RW_DOMAIN = os.environ.get("RAILWAY_TCP_PROXY_DOMAIN")
RW_PORT = os.environ.get("RAILWAY_TCP_PROXY_PORT")

def get_container_country():
    try:
        # استخدام مرآة أسرع لـ ipinfo
        return requests.get("https://ipinfo.io/country", timeout=3).text.strip()
    except:
        return "US"

def get_clean_ip(domain):
    if not domain: return "0.0.0.0"
    try:
        return socket.gethostbyname(domain)
    except:
        return domain

def send_telegram_notification():
    time.sleep(5) 
    ip = get_clean_ip(RW_DOMAIN)
    port = RW_PORT if RW_PORT else "11404"
    country = get_container_country()
    
    formatted_proxy = f"{USER}:{PASS}@{ip}:{port}"
    # طباعة البروكسي بالشكل المطلوب في اللوجات للنسخ السريع
    logger.info(f"🚀 HIGH-SPEED PROXY READY: {formatted_proxy}")

    msg = (
        f"<blockquote>🚀 <b>High-Speed Proxy Online</b></blockquote>\n\n"
        f"🌍 <b>Country:</b> {country}\n"
        f"🌐 <b>IP:</b> <code>{ip}</code>\n"
        f"🔌 <b>Port:</b> <code>{port}</code>\n"
        f"👤 <b>User:</b> <code>{USER}</code>\n"
        f"🔑 <b>Pass:</b> <code>{PASS}</code>\n\n"
        f"<blockquote><b>========== HTTP Custom ==========</b></blockquote>\n"
        f"<code>{formatted_proxy}</code>"
    )

    if TOKEN and OWNER_ID:
        try:
            requests.post(f"https://api.telegram.org/bot{TOKEN}/sendMessage", 
                          json={"chat_id": OWNER_ID, "text": msg, "parse_mode": "HTML"})
        except: pass

def tunnel(source, destination):
    try:
        source.settimeout(30)
        destination.settimeout(30)
        while True:
            # زيادة البافر لـ 32KB لرفع التقييم في سرعة النقل
            data = source.recv(32768)
            if not data: break
            destination.sendall(data)
    except: pass
    finally:
        try: source.close()
        except: pass
        try: destination.close()
        except: pass

def handle_client(client, addr):
    try:
        data = client.recv(1024)
        if not data: return

        # SOCKS5 - تحسين سرعة المصافحة
        if data[0] == 0x05:
            client.sendall(b"\x05\x02")
            auth_data = client.recv(512)
            client.sendall(b"\x01\x00")
            req = client.recv(512)
            atyp = req[3]
            if atyp == 1: dst = socket.inet_ntoa(req[4:8])
            elif atyp == 3: dst = req[5:5+req[4]].decode()
            port = struct.unpack(">H", req[-2:])[0]
            remote = socket.create_connection((dst, port), timeout=10)
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            
        # HTTP/HTTPS
        else:
            header = data.decode(errors='ignore')
            if f"Proxy-Authorization: Basic {AUTH_B64}" not in header:
                client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm='Proxy'\r\n\r\n")
                return
            
            line = header.split('\r\n')[0]
            url = line.split(' ')[1]
            if "CONNECT" in line:
                host, port = (url.split(':') if ":" in url else (url, 443))
                remote = socket.create_connection((host, int(port)), timeout=10)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                if "://" in url: url = url.split("://")[1]
                host_port = url.split("/")[0]
                host, port = (host_port.split(':') if ":" in host_port else (host_port, 80))
                remote = socket.create_connection((host, int(port)), timeout=10)
                remote.sendall(data)

        threading.Thread(target=tunnel, args=(client, remote), daemon=True).start()
        threading.Thread(target=tunnel, args=(remote, client), daemon=True).start()
    except:
        try: client.close()
        except: pass

def main():
    port = int(os.environ.get("PORT", 1080))
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(500)
    
    threading.Thread(target=send_telegram_notification, daemon=True).start()
    
    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()

if __name__ == "__main__":
    main()

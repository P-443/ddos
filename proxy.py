import socket
import struct
import os
import logging
import threading
import requests
import time
import redis  # تأكد من تثبيت مكتبة redis: pip install redis

# --- LOGGING ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
logger = logging.getLogger("ProxyEngine-Redis")

# --- CONFIG ---
TOKEN = os.environ.get("TELEGRAM_TOKEN")
OWNER_ID = os.environ.get("OWNER_ID")
RW_DOMAIN = os.environ.get("RAILWAY_TCP_PROXY_DOMAIN")
RW_PORT = os.environ.get("RAILWAY_TCP_PROXY_PORT")

# إعدادات Redis (أدخل الرابط الخاص بك هنا أو في المتغيرات البيئية)
REDIS_URL = os.environ.get("REDIS_URL", "redis://default:0YuZWX6ROoZZKBnpINhLVrmGHmW2arFKcj51BRt5NsOXpd3kavGnW9SpvQcO5JOS@147.93.55.93:5432")
db = redis.from_url(REDIS_URL, decode_responses=True)

# --- DATABASE OPERATIONS ---
def save_proxy_to_redis(proxy_str):
    try:
        # إضافة البروكسي لمجموعة (Set) لضمان عدم التكرار
        db.sadd("active_proxies", proxy_str)
        # جلب العدد الإجمالي
        return db.scard("active_proxies")
    except Exception as e:
        logger.error(f"Redis Error: {e}")
        return 0

def export_proxies_to_file():
    try:
        proxies = db.smembers("active_proxies")
        with open("proxy.txt", "w") as f:
            for p in proxies:
                f.write(p + "\n")
        return len(proxies)
    except Exception as e:
        logger.error(f"Export Error: {e}")
        return 0

# --- NOTIFICATION ---
def send_telegram_update():
    time.sleep(5)
    ip = socket.gethostbyname(RW_DOMAIN) if RW_DOMAIN else "0.0.0.0"
    port = RW_PORT if RW_PORT else "1080"
    
    current_proxy = f"{ip}:{port}"
    total_count = save_proxy_to_redis(current_proxy)
    export_proxies_to_file()

    msg = (
        f"🚀 <b>Proxy Node Online</b>\n"
        f"📍 Current: <code>{current_proxy}</code>\n"
        f"📊 Total Database Size: <b>{total_count}</b>"
    )

    if TOKEN and OWNER_ID:
        try:
            # إرسال النص
            requests.post(f"https://api.telegram.org/bot{TOKEN}/sendMessage", 
                          json={"chat_id": OWNER_ID, "text": msg, "parse_mode": "HTML"})
            # إرسال ملف proxy.txt
            with open("proxy.txt", "rb") as f:
                requests.post(f"https://api.telegram.org/bot{TOKEN}/sendDocument",
                              data={"chat_id": OWNER_ID}, files={"document": f})
        except Exception as e:
            logger.error(f"Telegram Error: {e}")

# --- TUNNELING & PROXY CORE ---
def tunnel(source, destination):
    try:
        source.settimeout(30)
        destination.settimeout(30)
        while True:
            data = source.recv(32768)
            if not data: break
            destination.sendall(data)
    except: pass
    finally:
        source.close()
        destination.close()

def handle_client(client, addr):
    try:
        data = client.recv(1024)
        if not data: return

        # SOCKS5 (بدون يوزر وباسورد)
        if data[0] == 0x05:
            client.sendall(b"\x05\x00")
            req = client.recv(512)
            atyp = req[3]
            if atyp == 1: dst = socket.inet_ntoa(req[4:8])
            elif atyp == 3: dst = req[5:5+req[4]].decode()
            port = struct.unpack(">H", req[-2:])[0]
            remote = socket.create_connection((dst, port), timeout=10)
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            
        # HTTP/HTTPS (بدون يوزر وباسورد)
        else:
            header = data.decode(errors='ignore')
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
        client.close()

def main():
    port = int(os.environ.get("PORT", 1080))
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(500)
    
    logger.info(f"Proxy Server Running on {port} | DB: Redis")
    threading.Thread(target=send_telegram_update, daemon=True).start()
    
    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()

if __name__ == "__main__":
    main()

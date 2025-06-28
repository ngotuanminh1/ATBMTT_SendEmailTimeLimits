# server.py - chạy ở MÁY NHẬN để chờ file
import socket
import os

HOST = "0.0.0.0"
PORT = 5001
SAVE_DIR = "received_packets"
os.makedirs(SAVE_DIR, exist_ok=True)

# Tạo socket và lắng nghe
s = socket.socket()
s.bind((HOST, PORT))
s.listen(1)
print(f"🟢 Đang chờ nhận file trên {HOST}:{PORT}...")

conn, addr = s.accept()
print(f"📥 Kết nối từ {addr}")

# Nhận tên file (kết thúc bằng '\n')
filename_bytes = b""
while not filename_bytes.endswith(b"\n"):
    byte = conn.recv(1)
    if not byte:
        break
    filename_bytes += byte
filename = filename_bytes.strip().decode()

# Ghi nội dung file nhận được
filepath = os.path.join(SAVE_DIR, filename)
with open(filepath, "wb") as f:
    while True:
        data = conn.recv(4096)
        if not data:
            break
        f.write(data)

print(f"✅ Đã nhận và lưu file: {filepath}")
conn.close()
s.close()

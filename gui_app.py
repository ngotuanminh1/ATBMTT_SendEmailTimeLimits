import customtkinter as ctk
from tkinter import filedialog, messagebox
import os, json, base64, hashlib, socket
from datetime import datetime, timedelta
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
import threading
import requests
from urllib.parse import urlparse, parse_qs

ROOM_DIR = "rooms"
os.makedirs(ROOM_DIR, exist_ok=True)

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class SecureApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Secure File Room")
        self.geometry("800x500")

        self.room_name = ctk.StringVar()
        self.room_password = ctk.StringVar()
        self.filename = None
        self.room_file = ""
        self.pwd_hash = ""
        self.timer_label = None

        self.build_login()

    def build_login(self):
        for widget in self.winfo_children():
            widget.destroy()

        wrapper = ctk.CTkFrame(self, width=350, height=300)
        wrapper.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(wrapper, text="🔐 Secure File Room", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(10, 20))

        ctk.CTkLabel(wrapper, text="Tên Room:").pack(anchor="w", padx=20)
        ctk.CTkEntry(wrapper, textvariable=self.room_name).pack(padx=20, fill="x")

        ctk.CTkLabel(wrapper, text="Mật khẩu:").pack(anchor="w", padx=20, pady=(10, 0))
        ctk.CTkEntry(wrapper, textvariable=self.room_password, show="*").pack(padx=20, fill="x")

        ctk.CTkButton(wrapper, text="🔓 Vào Room", command=self.enter_room).pack(pady=(20, 5), padx=20, fill="x")
        ctk.CTkButton(wrapper, text="➕ Tạo Room Mới", command=self.create_room).pack(padx=20, fill="x")

    def enter_room(self):
        room = self.room_name.get().strip()
        pwd = self.room_password.get().strip()
        if not room or not pwd:
            messagebox.showerror("Lỗi", "Không được để trống tên room hoặc mật khẩu")
            return

        self.room_file = os.path.join(ROOM_DIR, f"{room}.json")
        self.pwd_hash = hashlib.sha256(pwd.encode()).hexdigest()

        if not os.path.exists(self.room_file):
            messagebox.showerror("Lỗi", "Room này chưa được tạo")
            return

        try:
            with open(self.room_file, "r") as f:
                packet = json.load(f)
                if packet.get("pwd_hash") != self.pwd_hash:
                    messagebox.showerror("Lỗi", "Sai mật khẩu room")
                    return
        except:
            messagebox.showerror("Lỗi", "File room bị lỗi hoặc sai định dạng")
            return

        self.build_room_ui(room)

    def create_room(self):
        room = self.room_name.get().strip()
        pwd = self.room_password.get().strip()
        if not room or not pwd:
            messagebox.showerror("Lỗi", "Không được để trống tên room hoặc mật khẩu")
            return

        self.room_file = os.path.join(ROOM_DIR, f"{room}.json")
        if os.path.exists(self.room_file):
            messagebox.showerror("Lỗi", "Room đã tồn tại. Vui lòng chọn tên khác hoặc dùng 'Vào Room'")
            return

        self.pwd_hash = hashlib.sha256(pwd.encode()).hexdigest()
        with open(self.room_file, "w") as f:
            json.dump({"pwd_hash": self.pwd_hash}, f, indent=4)

        self.build_room_ui(room)

    def build_room_ui(self, room):
        for widget in self.winfo_children():
            widget.destroy()

        layout = ctk.CTkFrame(self)
        layout.pack(fill="both", expand=True, padx=10, pady=10)

        left = ctk.CTkFrame(layout, width=250)
        left.pack(side="left", fill="y", padx=10, pady=10)

        right = ctk.CTkFrame(layout)
        right.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(left, text=f"ROOM: {room}", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        ctk.CTkButton(left, text="📁 Chọn file", command=self.select_file).pack(pady=5)
        ctk.CTkButton(left, text="🔐 Mã hóa & lưu", command=self.encrypt_and_save).pack(pady=5)
        ctk.CTkButton(left, text="📥 Giải mã file", command=self.decrypt_file).pack(pady=5)
        ctk.CTkButton(left, text="🌐 Mã hóa từ Google Drive", command=self.encrypt_from_drive).pack(pady=5)
        ctk.CTkButton(left, text="📡 Gửi qua LAN", command=self.send_over_lan_custom).pack(pady=5)
        ctk.CTkButton(left, text="📨 Nhận từ LAN", command=self.receive_from_lan).pack(pady=5)
        ctk.CTkButton(left, text="🚪 Thoát Room", command=self.build_login).pack(pady=20)

        self.log = ctk.CTkTextbox(right)
        self.log.pack(fill="both", expand=True)

        self.timer_label = ctk.CTkLabel(left, text="")
        self.timer_label.pack(pady=(5, 0))

        if os.path.exists(self.room_file):
            try:
                with open(self.room_file, "r") as f:
                    packet = json.load(f)
                if "exp" in packet:
                    self.update_timer(packet["exp"])
            except:
                pass

            self.log_msg("📄 Đã tìm thấy file trong room. Bạn có thể giải mã.")

    def log_msg(self, msg):
        self.log.insert("end", msg + "\n")
        self.log.see("end")

    def update_timer(self, exp_str):
        try:
            exp_time = datetime.fromisoformat(exp_str.replace("Z", ""))
            now = datetime.utcnow()
            if now < exp_time:
                delta = exp_time - now
                self.timer_label.configure(text=f"⏳ Còn lại: {str(delta).split('.')[0]}")
                self.after(1000, lambda: self.update_timer(exp_str))
            else:
                self.timer_label.configure(text="⛔ Đã hết hạn")
        except:
            self.timer_label.configure(text="⚠️ Không thể xác định thời gian")

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.filename = file_path
            self.log_msg(f"📁 Đã chọn file: {os.path.basename(file_path)}")

    def encrypt_from_drive(self):
        def get_file_id(link):
            parsed = urlparse(link)
            if "id" in parse_qs(parsed.query):
                return parse_qs(parsed.query)["id"][0]
            elif "drive.google.com" in link:
                parts = parsed.path.split("/")
                if "d" in parts:
                    return parts[parts.index("d") + 1]
            return None

        def on_download():
            link = link_entry.get().strip()
            file_id = get_file_id(link)
            if not file_id:
                messagebox.showerror("Lỗi", "Không thể lấy ID từ link Drive")
                return

            try:
                url = f"https://drive.google.com/uc?id={file_id}&export=download"
                r = requests.get(url, allow_redirects=True)
                if r.status_code != 200 or b"Google Drive" in r.content:
                    raise Exception("Không thể tải file từ link. Hãy chắc chắn file chia sẻ là công khai.")

                os.makedirs("temp", exist_ok=True)
                tmp_file = os.path.join("temp", f"drive_{file_id}.bin")
                with open(tmp_file, "wb") as f:
                    f.write(r.content)

                self.filename = tmp_file
                self.encrypt_and_save()
                self.log_msg(f"🌐 Đã mã hóa file từ link Drive: {link}")

                try:
                    os.remove(tmp_file)
                except:
                    pass
            except Exception as e:
                self.log_msg(f"❌ Lỗi Drive: {str(e)}")
            finally:
                dialog.destroy()

        def on_download():
            link = link_entry.get().strip()
            file_id = get_file_id(link)
            if not file_id:
                messagebox.showerror("Lỗi", "Không thể lấy ID từ link Drive")
                return

            try:
                url = f"https://drive.google.com/uc?id={file_id}&export=download"
                r = requests.get(url)
                if r.status_code != 200:
                    raise Exception("Không thể tải file từ link")

                tmp_file = os.path.join("temp_download.bin")
                with open(tmp_file, "wb") as f:
                    f.write(r.content)
                self.filename = tmp_file
                self.encrypt_and_save()
                self.log_msg(f"🌐 Đã mã hóa file từ link Drive: {link}")
            except Exception as e:
                self.log_msg(f"❌ Lỗi Drive: {str(e)}")
            finally:
                dialog.destroy()

        dialog = ctk.CTkToplevel(self)
        dialog.title("Mã hóa từ Google Drive")
        dialog.geometry("400x150")
        ctk.CTkLabel(dialog, text="Nhập link Google Drive chia sẻ công khai").pack(pady=10)
        link_entry = ctk.CTkEntry(dialog, width=350)
        link_entry.pack(pady=5)
        ctk.CTkButton(dialog, text="Mã hóa", command=on_download).pack(pady=10)

    def encrypt_and_save(self):
        if not self.filename:
            messagebox.showerror("Lỗi", "Bạn chưa chọn file nào")
            return
        try:
            with open(self.filename, "rb") as f:
                plaintext = f.read()

            session_key = get_random_bytes(32)
            iv = get_random_bytes(16)
            cipher = AES.new(session_key, AES.MODE_CBC, iv)
            pad_len = 16 - len(plaintext) % 16
            ciphertext = cipher.encrypt(plaintext + bytes([pad_len] * pad_len))

            now = datetime.utcnow()
            expiration = (now + timedelta(hours=24)).isoformat() + "Z"
            hash_val = hashlib.sha512(iv + ciphertext + expiration.encode()).hexdigest()

            receiver_pub = RSA.import_key(open("keys/receiver_public.pem").read())
            encrypted_key = PKCS1_v1_5.new(receiver_pub).encrypt(session_key)

            sender_priv = RSA.import_key(open("keys/sender_private.pem").read())
            meta = f"{os.path.basename(self.filename)}|{now.isoformat()}"
            h = SHA512.new(meta.encode())
            signature = pkcs1_15.new(sender_priv).sign(h)

            packet = {
                "iv": base64.b64encode(iv).decode(),
                "cipher": base64.b64encode(ciphertext).decode(),
                "hash": hash_val,
                "sig": base64.b64encode(signature).decode(),
                "exp": expiration,
                "encrypted_key": base64.b64encode(encrypted_key).decode(),
                "filename": os.path.basename(self.filename),
                "timestamp": now.isoformat(),
                "pwd_hash": self.pwd_hash
            }

            with open(self.room_file, "w") as f:
                json.dump(packet, f, indent=4)

            self.log_msg("✅ File đã được mã hóa và lưu trong room")
            self.update_timer(expiration)
        except Exception as e:
            self.log_msg(f"❌ Lỗi khi mã hóa: {str(e)}")

    def decrypt_file(self):
        if not os.path.exists(self.room_file):
            messagebox.showerror("Lỗi", "Không tìm thấy file trong room")
            return
        try:
            with open(self.room_file, "r") as f:
                packet = json.load(f)

            if packet.get("pwd_hash") != self.pwd_hash:
                self.log_msg("❌ Sai mật khẩu phòng")
                return

            iv = base64.b64decode(packet["iv"])
            cipher_data = base64.b64decode(packet["cipher"])
            expiration = packet["exp"]
            if datetime.utcnow() > datetime.fromisoformat(expiration.replace("Z", "")):
                self.log_msg("❌ File đã hết hạn")
                return

            expected_hash = hashlib.sha512(iv + cipher_data + expiration.encode()).hexdigest()
            if expected_hash != packet["hash"]:
                self.log_msg("❌ Hash không khớp! Dữ liệu có thể đã bị thay đổi")
                return

            sender_pub = RSA.import_key(open("keys/sender_public.pem").read())
            meta = f"{packet['filename']}|{packet['timestamp']}"
            sig = base64.b64decode(packet["sig"])
            h = SHA512.new(meta.encode())
            pkcs1_15.new(sender_pub).verify(h, sig)

            receiver_priv = RSA.import_key(open("keys/receiver_private.pem").read())
            session_key = PKCS1_v1_5.new(receiver_priv).decrypt(base64.b64decode(packet["encrypted_key"]), get_random_bytes(16))

            cipher = AES.new(session_key, AES.MODE_CBC, iv)
            padded = cipher.decrypt(cipher_data)
            plaintext = padded[:-padded[-1]]

            out_file = f"received_{packet['filename']}"
            with open(out_file, "wb") as f:
                f.write(plaintext)

            self.log_msg(f"✅ Giải mã thành công. File đã lưu: {out_file}")
        except Exception as e:
            self.log_msg(f"❌ Lỗi khi giải mã: {str(e)}")

    def send_over_lan_custom(self):
        if not os.path.exists(self.room_file):
            messagebox.showerror("Lỗi", "Bạn chưa có file secure_packet.json để gửi")
            return

        dialog = ctk.CTkToplevel(self)
        dialog.title("Gửi qua LAN")
        dialog.geometry("300x150")
        ctk.CTkLabel(dialog, text="Nhập IP máy nhận (VD: 192.168.1.20)").pack(pady=10)
        ip_entry = ctk.CTkEntry(dialog)
        ip_entry.pack(pady=5)

        def on_send():
            ip = ip_entry.get().strip()
            dialog.destroy()
            if not ip:
                return
            try:
                s = socket.socket()
                s.connect((ip, 5001))
                s.sendall((os.path.basename(self.room_file) + "\n").encode())
                with open(self.room_file, "rb") as f:
                    while True:
                        data = f.read(4096)
                        if not data:
                            break
                        s.sendall(data)
                s.close()
                self.log_msg(f"📡 Đã gửi file đến {ip} thành công")
            except Exception as e:
                self.log_msg(f"❌ Gửi LAN lỗi: {str(e)}")

        ctk.CTkButton(dialog, text="Gửi", command=on_send).pack(pady=10)

    def receive_from_lan(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Nhận file LAN")
        dialog.geometry("300x180")
        ctk.CTkLabel(dialog, text="Chờ file từ LAN trên cổng 5001...").pack(pady=10)

        progress_label = ctk.CTkLabel(dialog, text="⏳ Đang chờ kết nối...")
        progress_label.pack(pady=5)

        def server_thread():
            try:
                s = socket.socket()
                s.bind(("", 5001))
                s.listen(1)
                conn, addr = s.accept()
                progress_label.configure(text=f"📥 Đang nhận từ {addr[0]}")

                filename = b""
                while not filename.endswith(b"\n"):
                    data = conn.recv(1)
                    if not data:
                        break
                    filename += data
                filename = filename.strip().decode()

                full_path = os.path.join(ROOM_DIR, filename)
                with open(full_path, "wb") as f:
                    while True:
                        data = conn.recv(4096)
                        if not data:
                            break
                        f.write(data)
                conn.close()
                s.close()

                self.log_msg(f"📥 Đã nhận file từ {addr[0]}: {filename}")

                room = self.room_name.get().strip()
                received_room_file = os.path.join(ROOM_DIR, f"{room}.json")
                if full_path == received_room_file:
                    self.room_file = full_path
                    self.log_msg("🔄 Tự động giải mã file sau khi nhận...")
                    self.decrypt_file()

                dialog.destroy()
            except Exception as e:
                self.log_msg(f"❌ Lỗi nhận LAN: {str(e)}")
                progress_label.configure(text="❌ Lỗi khi nhận file")

        threading.Thread(target=server_thread, daemon=True).start()

if __name__ == "__main__":
    app = SecureApp()
    app.mainloop()

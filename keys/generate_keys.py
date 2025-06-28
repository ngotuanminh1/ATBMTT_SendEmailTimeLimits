import os
from Crypto.PublicKey import RSA

KEY_DIR = "keys"
os.makedirs(KEY_DIR, exist_ok=True)

def create_key_pair(name):
    key = RSA.generate(2048)
    private_path = os.path.join(KEY_DIR, f"{name}_private.pem")
    public_path = os.path.join(KEY_DIR, f"{name}_public.pem")

    # Lưu private key
    with open(private_path, "wb") as f:
        f.write(key.export_key())

    # Lưu public key
    with open(public_path, "wb") as f:
        f.write(key.publickey().export_key())

    print(f"✔️ Tạo xong cặp khóa: {name}")

if __name__ == "__main__":
    create_key_pair("receiver")
    create_key_pair("sender")
    print("🎉 Hoàn tất! Các file đã lưu trong thư mục 'keys/'")

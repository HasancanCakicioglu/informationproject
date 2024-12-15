import tkinter as tk
from tkinter import scrolledtext, messagebox
import socketio
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import requests
import base64
import json

base_url = "https://informationproject.onrender.com"

# Generate RSA key pair for client
client_key = RSA.generate(2048)
client_public_key = client_key.publickey().export_key()


# Fetch server public key
response = requests.get(f"{base_url}/public-key")
server_public_key = RSA.import_key(response.text)

# Socket.IO client
sio = socketio.Client()

def encrypt_message(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    return base64.b64encode(cipher.encrypt(message.encode())).decode()

def decrypt_message(encrypted_message, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(base64.b64decode(encrypted_message)).decode()

def login():
    username = username_input.get()
    password = password_input.get()

    if not username or not password:
        messagebox.showerror("Error", "Please enter username and password.")
        return

    # Send login request
    try:
        response = requests.post(
            f"{base_url}/login",
            json={"username": username, "password": password},
        )
        if response.status_code == 200 and response.json().get("success"):
            messagebox.showinfo("Success", "Login successful!")
            show_chat_ui()
            sio.connect(base_url)
        else:
            messagebox.showerror("Error", "Invalid credentials.")
    except Exception as e:
        messagebox.showerror("Error", f"Login failed: {e}")

def send_message():
    message = message_input.get()
    if not message:
        return

    encrypted_message = encrypt_message(message, server_public_key)
    sio.emit('send-message',encrypted_message)

    chat_area.config(state=tk.NORMAL)
    chat_area.insert(tk.END, f"Me: {message}\n", "right")
    chat_area.config(state=tk.DISABLED)
    message_input.delete(0, tk.END)

def receive_message_adjust(data):
    try:
        decrypted_message = decrypt_message(data, client_key)
        chat_area.config(state=tk.NORMAL)
        chat_area.insert(tk.END, f"Friend: {decrypted_message}\n", "left")
        chat_area.config(state=tk.DISABLED)
    except Exception as e:
        print("Error decrypting message:", e)

@sio.event
def connect():
    sio.emit('register-key', client_public_key.decode())

@sio.on('receive-message')
def receive_message(data):
    receive_message_adjust(data)

@sio.event
def disconnect():
    print("Disconnected from server")

def show_chat_ui():
    login_frame.pack_forget()
    chat_frame.pack(fill=tk.BOTH, expand=True)

# GUI setup
root = tk.Tk()
root.title("Secure Chat App")

# Pencere boyutlarını ayarla
window_width = 500  # Genişlik
window_height = 400  # Yükseklik

# Ekran boyutlarını al
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

# Pencereyi ekranın ortasına yerleştirmek için pozisyon hesapla
x_position = (screen_width // 2) - (window_width // 2)
y_position = (screen_height // 2) - (window_height // 2)

# Pencerenin boyutunu ve konumunu ayarla
root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")

# Pencereyi yeniden boyutlandırmayı devre dışı bırakmak için (isteğe bağlı)
root.resizable(False, False)

login_frame = tk.Frame(root)
chat_frame = tk.Frame(root)

# Login UI
tk.Label(login_frame, text="Username").pack(pady=5)
username_input = tk.Entry(login_frame)
username_input.pack(pady=5)
tk.Label(login_frame, text="Password").pack(pady=5)
password_input = tk.Entry(login_frame, show="*")
password_input.pack(pady=5)
tk.Button(login_frame, text="Login", command=login).pack(pady=10)
login_frame.pack(fill=tk.BOTH, expand=True)

# Chat UI
chat_area = scrolledtext.ScrolledText(chat_frame, wrap=tk.WORD, state='disabled', height=20)
chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
chat_area.tag_configure("left", justify="left")
chat_area.tag_configure("right", justify="right")

message_input = tk.Entry(chat_frame, width=50)
message_input.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.X, expand=True)

send_button = tk.Button(chat_frame, text="Send", command=send_message)
send_button.pack(side=tk.RIGHT, padx=10, pady=10)

root.mainloop()

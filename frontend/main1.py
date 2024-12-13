import tkinter as tk
from tkinter import scrolledtext, messagebox
import socketio
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import requests
import base64

# Generate RSA key pair for client
client_key = RSA.generate(2048)
client_public_key = client_key.publickey().export_key()
client_private_key = client_key.export_key()

# Fetch server public key
response = requests.get("http://localhost:3000/public-key")
server_public_key = RSA.import_key(response.text)

# Socket.IO client
sio = socketio.Client()

# Encrypt and decrypt functions
def encrypt_message(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    return base64.b64encode(cipher.encrypt(message.encode())).decode()

def decrypt_message(encrypted_message, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(base64.b64decode(encrypted_message)).decode()

# Login function
def login():
    username = username_input.get()
    password = password_input.get()

    if not username or not password:
        messagebox.showerror("Error", "Please enter username and password.")
        return

    # Send login request
    try:
        response = requests.post("http://localhost:3000/login", json={"username": username, "password": password})
        if response.status_code == 200:
            messagebox.showinfo("Success", "Login successful!")
            login_window.destroy()
            connect_to_server()
        else:
            messagebox.showerror("Error", "Invalid credentials.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to connect: {e}")

# Connect to server
def connect_to_server():
    @sio.event
    def connect():
        print("Connected to server")
        sio.emit('register-key', client_public_key.decode())

    @sio.on('receive-message')
    def receive_message(data):
        receive_message_adjust(data)

    @sio.event
    def disconnect():
        print("Disconnected from server")

    sio.connect("http://localhost:3000")

# Send message function
def send_message():
    message = message_input.get()
    if not message:
        return

    encrypted_message = encrypt_message(message, server_public_key)
    sio.emit('send-message', encrypted_message)

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

# GUI setup for login
login_window = tk.Tk()
login_window.title("Login")
login_window.geometry("300x200")

login_frame = tk.Frame(login_window, padx=10, pady=10)
login_frame.pack(fill=tk.BOTH, expand=True)

username_label = tk.Label(login_frame, text="Username:")
username_label.pack(anchor="w")
username_input = tk.Entry(login_frame)
username_input.pack(fill=tk.X)

password_label = tk.Label(login_frame, text="Password:")
password_label.pack(anchor="w")
password_input = tk.Entry(login_frame, show="*")
password_input.pack(fill=tk.X)

login_button = tk.Button(login_frame, text="Login", command=login)
login_button.pack(pady=10)

login_window.mainloop()

# Main chat GUI
root = tk.Tk()
root.title("Secure Chat App")
root.geometry("500x600")

chat_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled', height=20, bg="#f0f0f0", font=("Arial", 12))
chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

chat_area.tag_configure("left", justify="left")
chat_area.tag_configure("right", justify="right")

message_input = tk.Entry(root, font=("Arial", 12))
message_input.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.X, expand=True)

send_button = tk.Button(root, text="Send", command=send_message, bg="#007BFF", fg="white", font=("Arial", 12, "bold"))
send_button.pack(side=tk.RIGHT, padx=10, pady=10)

root.mainloop()

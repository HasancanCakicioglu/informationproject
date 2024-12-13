import tkinter as tk
from tkinter import messagebox
import socketio
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import requests
import base64

# RSA key generation
client_key = RSA.generate(2048)
client_public_key = client_key.publickey().export_key()
client_private_key = client_key.export_key()

# Fetch the server's public key
response = requests.get("http://localhost:3000/public-key")
server_public_key = RSA.import_key(response.text)

# Socket.IO client
sio = socketio.Client()

def encrypt_message(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    return base64.b64encode(cipher.encrypt(message.encode())).decode()

def decrypt_message(encrypted_message, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(base64.b64decode(encrypted_message)).decode()

def send_message():
    message = message_input.get()
    if not message:
        return

    # Encrypt the message using server's public key
    encrypted_message = encrypt_message(message, server_public_key)
    sio.emit('send-message', encrypted_message)

    # Display the message in the chat window (align to the right)
    chat_area.config(state=tk.NORMAL)
    chat_area.insert(tk.END, f"Me: {message}\n", "right")
    chat_area.config(state=tk.DISABLED)
    message_input.delete(0, tk.END)

def receive_message_adjust(data):
    try:
        print("Received message:", data)
        decrypted_message = decrypt_message(data, client_key)
        chat_area.config(state=tk.NORMAL)
        chat_area.insert(tk.END, f"Friend: {decrypted_message}\n", "left")
        chat_area.config(state=tk.DISABLED)
        print("Decrypted message:", decrypted_message)
    except Exception as e:
        print("Error decrypting message:", e)

def login():
    username = username_input.get()
    password = password_input.get()
    
    if not username or not password:
        messagebox.showerror("Error", "Username or password cannot be empty")
        return

    # Encrypt the password using server's public key
    encrypted_password = encrypt_message(password, server_public_key)
    
    # Send login data to server
    sio.emit('login', {'username': username, 'encryptedPassword': encrypted_password})

# GUI setup
root = tk.Tk()
root.title("Secure Chat App")

# Login Form
login_frame = tk.Frame(root)
login_frame.pack(padx=10, pady=10)

tk.Label(login_frame, text="Username").grid(row=0, column=0, padx=5, pady=5)
username_input = tk.Entry(login_frame)
username_input.grid(row=0, column=1, padx=5, pady=5)

tk.Label(login_frame, text="Password").grid(row=1, column=0, padx=5, pady=5)
password_input = tk.Entry(login_frame, show="*")
password_input.grid(row=1, column=1, padx=5, pady=5)

login_button = tk.Button(login_frame, text="Login", command=login)
login_button.grid(row=2, columnspan=2, pady=10)

# Chat window (hidden until login)
chat_area = tk.Text(root, state=tk.DISABLED, height=15, width=50)
chat_area.pack(padx=10, pady=10)

message_input = tk.Entry(root, width=50)
message_input.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.X, expand=True)

send_button = tk.Button(root, text="Send", command=send_message)
send_button.pack(side=tk.RIGHT, padx=10, pady=10)

# Socket.IO events
@sio.event
def connect():
    print("Connected to server")

@sio.on('login-success')
def on_login_success(message):
    print(message)
    login_frame.pack_forget()  # Hide login form
    chat_area.config(state=tk.NORMAL)  # Enable chat area

@sio.on('login-failure')
def on_login_failure(message):
    print(message)
    messagebox.showerror("Login Failed", message)

@sio.on('receive-message')
def receive_message(data):
    print("Message received:", data)
    receive_message_adjust(data)

@sio.event
def disconnect():
    print("Disconnected from server")

# Connect to server
sio.connect("http://localhost:3000")
root.mainloop()

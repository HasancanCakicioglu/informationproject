import tkinter as tk
from tkinter import scrolledtext
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
    # Decrypt the message using client's private key
    try:
        print("Received message:", data)
        decrypted_message = decrypt_message(data, client_key)
        chat_area.config(state=tk.NORMAL)
        chat_area.insert(tk.END, f"Friend: {decrypted_message}\n", "left")
        chat_area.config(state=tk.DISABLED)
        print("Decrypted message:", decrypted_message)
    except Exception as e:
        print("Error decrypting message:", e)

# GUI setup
root = tk.Tk()
root.title("Secure Chat App")

chat_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled', height=20)
chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

# Add custom tags for text alignment
chat_area.tag_configure("left", justify="left")
chat_area.tag_configure("right", justify="right")

message_input = tk.Entry(root, width=50)
message_input.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.X, expand=True)

send_button = tk.Button(root, text="Send", command=send_message)
send_button.pack(side=tk.RIGHT, padx=10, pady=10)

# Connect to server
@sio.event
def connect():
    print("Connected to server")
    # Register client's public key
    sio.emit('register-key', client_public_key.decode())

@sio.on('receive-message')
def receive_message(data):
    print("Message received:", data)
    receive_message_adjust(data)

@sio.event
def disconnect():
    print("Disconnected from server")

# Start the connection
sio.connect("http://localhost:3000")
root.mainloop()

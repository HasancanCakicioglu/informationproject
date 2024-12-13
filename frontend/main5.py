import tkinter as tk
from tkinter import messagebox, scrolledtext
import socketio
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import requests
import base64

# Kullanıcı adı ve şifre doğrulama
users = [
    { "username": "alice", "password": "password123" },
    { "username": "bob", "password": "securepass" }
]

# RSA Anahtar Çifti Oluşturma (Müşteri için)
client_key = RSA.generate(2048)
client_public_key = client_key.publickey().export_key()
client_private_key = client_key.export_key()

# Sunucu Genel Anahtarını Alma
response = requests.get("http://localhost:3000/public-key")
server_public_key = RSA.import_key(response.text)   

# Socket.IO Client
sio = socketio.Client()

# Mesajı şifrele
def encrypt_message(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    return base64.b64encode(cipher.encrypt(message.encode())).decode()

# Şifreli mesajı çöz
def decrypt_message(encrypted_message, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(base64.b64decode(encrypted_message)).decode()

# Mesaj gönderme
def send_message():
    message = message_input.get()
    if not message:
        return

    # Mesajı sunucunun genel anahtarı ile şifrele
    encrypted_message = encrypt_message(message, server_public_key)
    sio.emit('send-message', encrypted_message)

    # Mesajı sohbet penceresinde göster (sağa hizalı)
    chat_area.config(state=tk.NORMAL)
    chat_area.insert(tk.END, f"Me: {message}\n", "right")
    chat_area.config(state=tk.DISABLED)
    message_input.delete(0, tk.END)

# Mesajı al ve çöz
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

# Giriş ekranını oluşturma
def login_screen():
    def check_login():
        username = username_input.get()
        password = password_input.get()

        # Kullanıcı adı ve şifreyi kontrol etme
        for user in users:
            if user["username"] == username and user["password"] == password:
                messagebox.showinfo("Login Successful", "Giriş başarılı!")
                login_window.destroy()  # Giriş penceresini kapatma
                open_chat_screen()  # Mesajlaşma ekranını açma
                return
        
        messagebox.showerror("Login Failed", "Kullanıcı adı veya şifre yanlış.")

    # Giriş penceresi
    login_window = tk.Tk()
    login_window.title("Login Screen")

    # Kullanıcı adı etiketi ve giriş alanı
    tk.Label(login_window, text="Username").grid(row=0, column=0, padx=5, pady=5)
    username_input = tk.Entry(login_window)
    username_input.grid(row=0, column=1, padx=5, pady=5)

    # Şifre etiketi ve giriş alanı
    tk.Label(login_window, text="Password").grid(row=1, column=0, padx=5, pady=5)
    password_input = tk.Entry(login_window, show="*")
    password_input.grid(row=1, column=1, padx=5, pady=5)

    # Giriş butonu
    login_button = tk.Button(login_window, text="Login", command=check_login)
    login_button.grid(row=2, columnspan=2, pady=10)

    login_window.mainloop()

# Sohbet ekranını oluşturma
def open_chat_screen():
    global message_input, chat_area, send_button

    chat_window = tk.Tk()
    chat_window.title("Secure Chat App")

    chat_area = scrolledtext.ScrolledText(chat_window, wrap=tk.WORD, state='disabled', height=20)
    chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    # Özel etiketler ekleyerek metin hizalama
    chat_area.tag_configure("left", justify="left")
    chat_area.tag_configure("right", justify="right")

    message_input = tk.Entry(chat_window, width=50)
    message_input.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.X, expand=True)

    send_button = tk.Button(chat_window, text="Send", command=send_message)
    send_button.pack(side=tk.RIGHT, padx=10, pady=10)

    # Server'a bağlanmak için gerekli fonksiyonları tanımla
    @sio.event
    def connect():
        print("Connected to server")
        # Client'ın genel anahtarını kaydet
        sio.emit('register-key', client_public_key.decode())

    @sio.on('receive-message')
    def receive_message(data):
        print("Message received:", data)
        receive_message_adjust(data)

    @sio.event
    def disconnect():
        print("Disconnected from server")

    # Sunucuya bağlan
    sio.connect("http://localhost:3000")
    chat_window.mainloop()

# İlk olarak giriş ekranını aç
login_screen()

import os
import mysql.connector
import tkinter as tk
from tkinter import ttk, messagebox
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES, ChaCha20
from Crypto.Util.Padding import pad, unpad

# Key generation function using PBKDF2
def generate_key(password: str, salt: bytes) -> bytes:
    return pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)

# ChaCha20 encryption
def chacha20_encrypt(key: bytes, plaintext: bytes, nonce: bytes) -> bytes:
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.encrypt(plaintext)

# ChaCha20 decryption
def chacha20_decrypt(key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(ciphertext)

# AES encryption
def aes_encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, AES.block_size))

# AES decryption
def aes_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

# Database functions
def create_db():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Nabapurai@0003",
            database="encryption_app"
        )
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ciphertext BLOB NOT NULL,
                nonce_or_iv BLOB NOT NULL,
                salt BLOB NOT NULL,
                encryption_method VARCHAR(10) NOT NULL
            )
        ''')
        conn.commit()
        conn.close()
    except mysql.connector.Error as e:
        print(f"MySQL error: {e}")
        messagebox.showerror("Database Error", f"An error occurred while accessing the database: {e}")

def save_message(ciphertext: bytes, nonce_or_iv: bytes, salt: bytes, method: str):
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Nabapurai@0003",
            database="encryption_app"
        )
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO messages (ciphertext, nonce_or_iv, salt, encryption_method)
            VALUES (%s, %s, %s, %s)
        ''', (ciphertext, nonce_or_iv, salt, method))
        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "Message encrypted and stored in the database!")
    except mysql.connector.Error as e:
        print(f"MySQL error: {e}")
        messagebox.showerror("Database Error", f"An error occurred while saving the message: {e}")

def fetch_messages():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Nabapurai@0003",
            database="encryption_app"
        )
        cursor = conn.cursor()
        cursor.execute('SELECT id, ciphertext, nonce_or_iv, salt, encryption_method FROM messages')
        messages = cursor.fetchall()
        conn.close()
        return messages
    except mysql.connector.Error as e:
        print(f"MySQL error: {e}")
        messagebox.showerror("Database Error", f"An error occurred while fetching messages: {e}")
        return []

# Encrypt message
def encrypt_message(password_entry, message_entry, encryption_method):
    password = password_entry.get()
    message = message_entry.get()

    if not password or not message:
        messagebox.showerror("Input Error", "Password and message cannot be empty!")
        return

    # Generate a random salt (for key derivation)
    salt = os.urandom(16)
    key = generate_key(password, salt)

    # Encrypt the message
    method = encryption_method.get()
    if method == "ChaCha20":
        nonce = os.urandom(12)  # ChaCha20 requires a 12-byte nonce
        ciphertext = chacha20_encrypt(key, message.encode(), nonce)
        save_message(ciphertext, nonce, salt, "ChaCha20")
    elif method == "AES":
        iv = os.urandom(16)  # AES requires a 16-byte IV
        ciphertext = aes_encrypt(key, message.encode(), iv)
        save_message(ciphertext, iv, salt, "AES")
    else:
        messagebox.showerror("Input Error", "Please select an encryption method.")

# Decrypt message
def decrypt_message(password_entry, message_id_entry, decryption_result_label):
    password = password_entry.get()
    message_id = message_id_entry.get()

    if not password or not message_id:
        messagebox.showerror("Input Error", "Password and Message ID cannot be empty!")
        return

    try:
        message_id = int(message_id)
    except ValueError:
        messagebox.showerror("Input Error", "Message ID must be a valid integer!")
        return

    # Fetch the message from the database
    messages = fetch_messages()
    message = None
    for msg in messages:
        if msg[0] == message_id:
            message = msg
            break

    if not message:
        messagebox.showerror("Error", "Message ID not found!")
        return

    # Extract data from the message
    ciphertext = message[1]
    nonce_or_iv = message[2]
    salt = message[3]
    method = message[4]

    # Derive the key
    key = generate_key(password, salt)

    # Decrypt the message
    try:
        if method == "ChaCha20":
            plaintext = chacha20_decrypt(key, ciphertext, nonce_or_iv)
        elif method == "AES":
            plaintext = aes_decrypt(key, ciphertext, nonce_or_iv)
        else:
            messagebox.showerror("Error", "Unsupported encryption method!")
            return

        # Display the decrypted message
        decryption_result_label.config(text=f"Decrypted Message: {plaintext.decode()}")
    except Exception as e:
        messagebox.showerror("Decryption Error", f"An error occurred during decryption: {e}")

# Gradient background for frames
class GradientFrame(tk.Canvas):
    def __init__(self, parent, color1, color2, **kwargs):
        tk.Canvas.__init__(self, parent, **kwargs)
        self.color1 = color1
        self.color2 = color2
        self.bind("<Configure>", self._draw_gradient)

    def _draw_gradient(self, event=None):
        self.delete("gradient")
        width = self.winfo_width()
        height = self.winfo_height()
        for i in range(height):
            r = int((self.color1[0] * (height - i) + self.color2[0] * i) / height)
            g = int((self.color1[1] * (height - i) + self.color2[1] * i) / height)
            b = int((self.color1[2] * (height - i) + self.color2[2] * i) / height)
            color = f"#{r:02x}{g:02x}{b:02x}"
            self.create_line(0, i, width, i, tags=("gradient",), fill=color)
        self.lower("gradient")

# Main Tkinter GUI
def main():
    root = tk.Tk()
    root.title("Secure Messenger App")
    root.geometry("1000x600")
    root.configure(bg="#2E3440")  # Dark background

    # Custom style for ttk widgets
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TFrame", background="#3B4252")
    style.configure("TLabel", background="#3B4252", foreground="#ECEFF4", font=("Helvetica", 12))
    style.configure("TButton", background="#81A1C1", foreground="#2E3440", font=("Helvetica", 12), padding=10)
    style.configure("TRadiobutton", background="#3B4252", foreground="#ECEFF4", font=("Helvetica", 12))
    style.configure("TEntry", font=("Helvetica", 12))

    # Create Database if not exists
    create_db()

    # Gradient background for the main window
    gradient_frame = GradientFrame(root, (46, 52, 64), (59, 66, 82))
    gradient_frame.grid(row=0, column=0, columnspan=2, sticky="nsew")

    # Encryption Section (Left Side)
    encryption_frame = ttk.LabelFrame(gradient_frame, text="Encryption", padding=20)
    encryption_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")

    password_label = ttk.Label(encryption_frame, text="Enter Password:")
    password_label.pack(pady=5)
    password_entry = ttk.Entry(encryption_frame, show="*")
    password_entry.pack(pady=5)

    message_label = ttk.Label(encryption_frame, text="Enter Message:")
    message_label.pack(pady=5)
    message_entry = ttk.Entry(encryption_frame)
    message_entry.pack(pady=5)

    encryption_method_label = ttk.Label(encryption_frame, text="Select Encryption Method:")
    encryption_method_label.pack(pady=5)
    encryption_method = tk.StringVar(value="ChaCha20")
    cha_chacha20_radio = ttk.Radiobutton(encryption_frame, text="ChaCha20", variable=encryption_method, value="ChaCha20")
    aes_radio = ttk.Radiobutton(encryption_frame, text="AES", variable=encryption_method, value="AES")
    cha_chacha20_radio.pack(pady=5)
    aes_radio.pack(pady=5)

    encrypt_button = ttk.Button(
        encryption_frame, 
        text="Encrypt and Store Message", 
        command=lambda: encrypt_message(password_entry, message_entry, encryption_method)
    )
    encrypt_button.pack(pady=20)

    # Decryption Section (Right Side)
    decryption_frame = ttk.LabelFrame(gradient_frame, text="Decryption", padding=20)
    decryption_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")

    decryption_password_label = ttk.Label(decryption_frame, text="Enter Password:")
    decryption_password_label.pack(pady=5)
    decryption_password_entry = ttk.Entry(decryption_frame, show="*")
    decryption_password_entry.pack(pady=5)

    message_id_label = ttk.Label(decryption_frame, text="Enter Message ID:")
    message_id_label.pack(pady=5)
    message_id_entry = ttk.Entry(decryption_frame)
    message_id_entry.pack(pady=5)

    decrypt_button = ttk.Button(
        decryption_frame, 
        text="Decrypt Message", 
        command=lambda: decrypt_message(decryption_password_entry, message_id_entry, decryption_result_label)
    )
    decrypt_button.pack(pady=20)

    decryption_result_label = ttk.Label(decryption_frame, text="Decrypted Message: ", wraplength=300)
    decryption_result_label.pack(pady=10)

    # Configure grid weights to make the frames expandable
    root.grid_columnconfigure(0, weight=1)
    root.grid_columnconfigure(1, weight=1)
    root.grid_rowconfigure(0, weight=1)

    # Simple animation for buttons (hover effect)
    def on_enter(e):
        e.widget['style'] = 'Hover.TButton'

    def on_leave(e):
        e.widget['style'] = 'TButton'

    style.configure("Hover.TButton", background="#88C0D0")
    for button in [encrypt_button, decrypt_button]:
        button.bind("<Enter>", on_enter)
        button.bind("<Leave>", on_leave)

    root.mainloop()

if __name__ == "__main__":
    main()
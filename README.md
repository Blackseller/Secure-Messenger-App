# Secure Messenger App

## Description

The **Secure Messenger App** is a Python-based application that allows users to securely encrypt and decrypt messages using two encryption algorithms: **AES** and **ChaCha20**. The application uses a **Tkinter GUI** for a simple user interface and stores encrypted messages in a **MySQL database**. The key derivation process uses **PBKDF2** to securely generate encryption keys from a password.

### Features:
- Encrypt and decrypt messages using **AES** (Advanced Encryption Standard) and **ChaCha20** algorithms.
- Securely store encrypted messages in a **MySQL** database.
- Password-based key generation with **PBKDF2** for both encryption algorithms.
- A sleek GUI built with **Tkinter** for ease of use.

### Technologies Used:
- Python 3
- Tkinter for GUI
- MySQL for database management
- **PyCryptodome** library for encryption
- **mysql-connector** library for MySQL database connectivity

### Installation:
1. Clone the repository:
   ```bash
   git clone https://github.com/Blackseller/secure-messenger-app.git

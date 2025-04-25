import tkinter as tk
from tkinter import scrolledtext, simpledialog
import socket
import threading
import json
import base64
import os
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


"""
SecureChatApp
A GUI-based secure chatting application utilizing AES-GCM, PBKDF2, web sockets
to transfer information, and JSON to format messages. 

© 2025 Zachary "Claude" Lilley - Thorpe Mayes - Javier Zertuche. All rights reserved.
"""
class SecureChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure P2P Chat")
        self.root.geometry("600x600")
        
        # Connection variables
        self.connected = False
        self.socket = None
        self.peer_address = None
        self.listen_thread = None
        self.is_alice = None
        
        # Encryption variables
        self.password = None
        self.key = None
        self.key_update_interval = 30 * 60  # Key will update every 30 minutes 
        self.key_update_timer = None
        self.message_counter = 0
        
        # UI setup
        self.root
        self.setup_ui()

    """
    The main entry point of the program
    """
    def setup_ui(self):
        # Main frame
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        
        # Connection frame
        conn_frame = tk.Frame(main_frame)
        conn_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(conn_frame, text="Host:").pack(side=tk.LEFT, padx=5)
        self.host_entry = tk.Entry(conn_frame, width=15)
        self.host_entry.insert(0, "127.0.0.1")
        self.host_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Label(conn_frame, text="Port:").pack(side=tk.LEFT, padx=5)
        self.port_entry = tk.Entry(conn_frame, width=6)
        self.port_entry.insert(0, "12345")
        self.port_entry.pack(side=tk.LEFT, padx=5)
        
        self.connect_button = tk.Button(conn_frame, text="Connect as Bob", command=self.connect_as_bob)
        self.connect_button.pack(side=tk.LEFT, padx=5)
        
        self.listen_button = tk.Button(conn_frame, text="Listen as Alice", command=self.listen_as_alice)
        self.listen_button.pack(side=tk.LEFT, padx=5)
        
        self.status_label = tk.Label(conn_frame, text="Disconnected", fg="red")
        self.status_label.pack(side=tk.RIGHT, padx=5)
        
        # Password frame
        pass_frame = tk.Frame(main_frame)
        pass_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(pass_frame, text="Shared Password:").pack(side=tk.LEFT, padx=5)
        self.password_entry = tk.Entry(pass_frame, width=30, show="*") # hide password from view
        
        self.password_entry.pack(side=tk.LEFT, padx=5)
        
        self.set_password_button = tk.Button(pass_frame, text="Set Password", command=self.set_password)
        self.set_password_button.pack(side=tk.LEFT, padx=5)
        
        # Chat display
        chat_frame = tk.Frame(main_frame)
        chat_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.chat_display = scrolledtext.ScrolledText(chat_frame, wrap=tk.WORD, state='disabled')
        self.chat_display.pack(fill=tk.BOTH, expand=True)
        
        # Message entry
        msg_frame = tk.Frame(main_frame)
        msg_frame.pack(fill=tk.X, pady=5)
        
        self.message_entry = tk.Entry(msg_frame)
        self.message_entry.pack(fill=tk.X, side=tk.LEFT, expand=True, padx=5)
        self.message_entry.bind("<Return>", self.send_message)
        
        self.send_button = tk.Button(msg_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT, padx=5)
        
        # Key management frame
        key_frame = tk.Frame(main_frame)
        key_frame.pack(fill=tk.X, pady=5)
        
        self.update_key_button = tk.Button(key_frame, text="Update Key", command=self.manually_update_key, state=tk.DISABLED)
        self.update_key_button.pack(side=tk.LEFT, padx=5)
        
        self.key_status = tk.Label(key_frame, text="No key established")
        self.key_status.pack(side=tk.LEFT, padx=5)
    
    def add_message(self, message, ciphertext=None):
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, message + "\n")
        if ciphertext:
            self.chat_display.insert(tk.END, f"Ciphertext: {ciphertext}\n\n")
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)
    
    def set_password(self):
        password = self.password_entry.get()
        if not password:
            self.add_message("Error: Password cannot be empty")
            return
        
        self.password = password
        self.update_key()
        self.update_key_button.config(state=tk.NORMAL)
        self.add_message("Password set and initial key derived")
        self.schedule_key_update()
    
    def derive_key_from_password(self, salt):
        # # Generate a random salt if not provided
        # if salt is None:
        #     salt = os.urandom(16)
        
        # Use PBKDF2 to derive a 256-bit key
        kdf = PBKDF2HMAC( # key derivation function
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=salt,
            iterations=100000,
        )
        
        self.key = kdf.derive(self.password.encode())
        self.key_status.config(text=f"Key established: {base64.b64encode(self.key[:8]).decode()}...")



        return salt  # Return salt so it can be shared
    
    def encrypt_message(self, plaintext):
        # Generate a random nonce for this message (12 bytes for AES-GCM)
        nonce = os.urandom(12)
        
        # Encrypt the message using AES-GCM
        aesgcm = AESGCM(self.key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        
        # Combine nonce and ciphertext for transmission
        encrypted_data = {
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
        }
        
        return encrypted_data, base64.b64encode(ciphertext).decode()
    
    def decrypt_message(self, encrypted_data):
        nonce = base64.b64decode(encrypted_data["nonce"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        
        # Decrypt the message
        aesgcm = AESGCM(self.key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        return plaintext.decode()
    
    def listen_as_alice(self):
        if self.connected:
            self.add_message("Already connected")
            return
        
        try:
            port = int(self.port_entry.get())
            host = self.host_entry.get()
            
            # Create a server socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((host, port))
            server_socket.listen(1)
            
            self.add_message(f"Listening on {host}:{port}...")
            self.status_label.config(text="Listening...", fg="orange")
            
            # Start a thread to accept the connection
            def accept_connection():
                client_socket, client_address = server_socket.accept()
                self.socket = client_socket
                self.peer_address = client_address
                self.connected = True
                self.is_alice = True
                
                self.add_message(f"Connected to {client_address[0]}:{client_address[1]}")
                self.status_label.config(text=f"Connected to {client_address[0]}", fg="green")
                
                # Start the listening thread
                self.listen_thread = threading.Thread(target=self.listen_for_messages)
                self.listen_thread.daemon = True
                self.listen_thread.start()
                
                # Close the server socket now that we have a connection
                server_socket.close()
            
            threading.Thread(target=accept_connection).start()
            
        except Exception as e:
            self.add_message(f"Error starting server: {e}")
    
    def connect_as_bob(self):
        if self.connected:
            self.add_message("Already connected")
            return
        
        try:
            port = int(self.port_entry.get())
            host = self.host_entry.get()
            
            # Create a client socket
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((host, port))
            
            self.socket = client_socket
            self.peer_address = (host, port)
            self.connected = True
            self.is_alice = False
            
            self.add_message(f"Connected to {host}:{port}")
            self.status_label.config(text=f"Connected to {host}", fg="green")
            
            # Start the listening thread
            self.listen_thread = threading.Thread(target=self.listen_for_messages)
            self.listen_thread.daemon = True
            self.listen_thread.start()
            
        except Exception as e:
            self.add_message(f"Error connecting: {e}")
    
    def listen_for_messages(self):
        while self.connected:
            try:
                # First, receive the message length
                length_data = self.socket.recv(4)
                if not length_data:
                    break
                
                message_length = int.from_bytes(length_data, byteorder='big')
                
                # Then receive the full message
                data = b''
                while len(data) < message_length:
                    chunk = self.socket.recv(min(4096, message_length - len(data)))
                    if not chunk:
                        break
                    data += chunk
                
                if not data:
                    break
                
                # Parse the JSON data
                message_data = json.loads(data.decode())
                
                if message_data.get("type") == "chat":
                    # Regular chat message
                    encrypted_data = message_data["data"]
                    display_ciphertext = encrypted_data["ciphertext"]
                    
                    try:
                        plaintext = self.decrypt_message(encrypted_data)
                        self.add_message(f"Received: {plaintext}", display_ciphertext)
                    except Exception as e:
                        self.add_message(f"Error decrypting message: {e}", display_ciphertext)
                
                elif message_data.get("type") == "key_update":
                    # Key update message
                    try:
                        salt = base64.b64decode(message_data["salt"])
                        self.derive_key_from_password(salt)
                        self.add_message("Key updated with salt from peer")
                    except Exception as e:
                        self.add_message(f"Error updating key: {e}")
            
            except Exception as e:
                self.add_message(f"Error receiving message: {e}")
                break
        
        self.connected = False
        self.status_label.config(text="Disconnected", fg="red")
        self.add_message("Disconnected from peer")
    
    def send_message(self, event=None):
        message = self.message_entry.get()
        if not message:
            return
        
        if not self.connected:
            self.add_message("Error: Not connected")
            return
        
        if not self.key:
            self.add_message("Error: Password not set")
            return
        
        try:
            # Encrypt the message
            encrypted_data, display_ciphertext = self.encrypt_message(message)
            
            # Prepare the message for sending
            message_data = {
                "type": "chat",
                "data": encrypted_data
            }
            
            json_data = json.dumps(message_data).encode()
            
            # Send the length first, then the message
            self.socket.sendall(len(json_data).to_bytes(4, byteorder='big')) 
            self.socket.sendall(json_data)
            
            self.add_message(f"You: {message}", display_ciphertext)
            self.message_entry.delete(0, tk.END) # resets message field
            
            # Increment message counter
            self.message_counter += 1
            
        except Exception as e:
            self.add_message(f"Error sending message: {e}")
    
    def schedule_key_update(self):
        # Cancel any existing timer
        if self.key_update_timer:
            self.root.after_cancel(self.key_update_timer)
        
        # Schedule next key update
        self.key_update_timer = self.root.after(
            self.key_update_interval * 1000,  # Convert to milliseconds
            self.update_key
        )
    
    def update_key(self):
        if not self.connected or not self.password:
            return
        
        try:
            # Generate new salt
            new_salt = os.urandom(16)
            
            # Derive new key
            self.derive_key_from_password(new_salt)
            
            # Send the salt to peer
            message_data = {
                "type": "key_update",
                "salt": base64.b64encode(new_salt).decode()
            }
            
            json_data = json.dumps(message_data).encode()
            
            # Send the length first, then the message
            self.socket.sendall(len(json_data).to_bytes(4, byteorder='big'))
            self.socket.sendall(json_data)
            
            self.add_message("Key updated and new salt sent to peer")
            
            # Schedule next update
            self.schedule_key_update()
            
        except Exception as e:
            self.add_message(f"Error updating key: {e}")
    
    def manually_update_key(self):
        self.update_key()

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatApp(root)
    root.mainloop()
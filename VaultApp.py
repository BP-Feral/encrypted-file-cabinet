import customtkinter as ctk
from tkinter import messagebox, filedialog
import sys
import os
import shutil
import hashlib
import base64
from cryptography.fernet import Fernet
import subprocess
import platform

# Detect base directory (next to .exe or .py file)
if getattr(sys, 'frozen', False):
    base_dir = os.path.dirname(sys.executable)
else:
    base_dir = os.path.dirname(os.path.abspath(__file__))

# Vault and unvaulted directories relative to the executable
vault_dir = os.path.join(base_dir, "vault")
unvaulted_dir = os.path.join(base_dir, "unvaulted")

# Ensure both directories exist
os.makedirs(vault_dir, exist_ok=True)
os.makedirs(unvaulted_dir, exist_ok=True)


# Function to create a valid Fernet key from password
def create_fernet_key(password):
    # Hash the password using SHA-256
    password_hash = hashlib.sha256(password.encode()).digest()
    
    # Base64 encode the hash to get the Fernet key (32 bytes)
    fernet_key = base64.urlsafe_b64encode(password_hash)
    
    return fernet_key

# Encrypt and decrypt file
def encrypt_file(file_path, password):
    fernet_key = create_fernet_key(password)
    fernet = Fernet(fernet_key)
    
    with open(file_path, 'rb') as file:
        data = file.read()
    
    encrypted = fernet.encrypt(data)
    encrypted_file_path = os.path.join(vault_dir, os.path.basename(file_path) + ".enc")
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

def decrypt_file(encrypted_file_path, password):
    fernet_key = create_fernet_key(password)
    fernet = Fernet(fernet_key)
    
    with open(encrypted_file_path, 'rb') as file:
        encrypted_data = file.read()
    
    decrypted = fernet.decrypt(encrypted_data)
    decrypted_file_path = os.path.join(unvaulted_dir, os.path.basename(encrypted_file_path[:-4]))  # Remove '.enc' and add to "unvaulted"
    
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted)

# CustomTkinter UI
class FileCabinetApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted File Cabinet")
        self.password = None
        
        # Set appearance mode and color scheme
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        # Login Screen
        self.password_label = ctk.CTkLabel(root, text="Enter Password:", font=("Arial", 14))
        self.password_label.pack(pady=20)
        
        self.password_entry = ctk.CTkEntry(root, show="*", width=250, font=("Arial", 14))
        self.password_entry.pack(pady=10)
        
        self.submit_button = ctk.CTkButton(root, text="Submit", command=self.authenticate, font=("Arial", 14))
        self.submit_button.pack(pady=20)

    def view_file_location(self, file_name):
        file_path = os.path.join(vault_dir, file_name)
        directory_path = os.path.dirname(file_path)  # Get the directory path
        
        try:
            if platform.system() == "Windows":
                os.startfile(directory_path)  # Open the directory
            elif platform.system() == "Darwin":  # macOS
                subprocess.run(["open", directory_path])  # Open the directory
            else:  # Linux
                subprocess.run(["xdg-open", directory_path])  # Open the directory
        except Exception as e:
            messagebox.showerror("Error", f"Could not open file location: {e}")
            
    def authenticate(self):
        password = self.password_entry.get()
        try:
            self.password = password
            self.password_entry.delete(0, ctk.END)
            self.show_vault()
        except Exception as e:
            messagebox.showerror("Error", f"Authentication failed: {e}")

    def show_vault(self):
        # Destroy login screen widgets
        for widget in self.root.winfo_children():
            widget.destroy()

        # Vault UI
        self.frame = ctk.CTkScrollableFrame(self.root, width=700, height=350)
        self.frame.pack(pady=20)

        # Display existing files
        self.update_file_list()

        # Button row (Refresh, Add File, Re-enter Password, Open Unvaulted)
        button_row = ctk.CTkFrame(self.root)
        button_row.pack(pady=10)

        self.refresh_button = ctk.CTkButton(button_row, text="↻ Refresh", width=100, command=self.update_file_list, font=("Arial", 12))
        self.refresh_button.grid(row=0, column=0, padx=10)

        self.add_file_button = ctk.CTkButton(button_row, text="+ Add File", width=100, command=self.add_file, font=("Arial", 12))
        self.add_file_button.grid(row=0, column=1, padx=10)

        self.reset_password_button = ctk.CTkButton(button_row, text="🔐 Re-enter Password", width=140, command=self.reset_password, font=("Arial", 12))
        self.reset_password_button.grid(row=0, column=2, padx=10)

        self.open_unvaulted_button = ctk.CTkButton(button_row, text="📂 Open Unvaulted", width=140, command=self.open_unvaulted, font=("Arial", 12))
        self.open_unvaulted_button.grid(row=0, column=3, padx=10)

    def reset_password(self):
        # Clear vault UI and go back to password prompt
        for widget in self.root.winfo_children():
            widget.destroy()
        self.__init__(self.root)
    
    def open_unvaulted(self):
        try:
            if platform.system() == "Windows":
                os.startfile(unvaulted_dir)  # Open the unvaulted folder
            elif platform.system() == "Darwin":  # macOS
                subprocess.run(["open", unvaulted_dir])  # Open the unvaulted folder
            else:  # Linux
                subprocess.run(["xdg-open", unvaulted_dir])  # Open the unvaulted folder
        except Exception as e:
            messagebox.showerror("Error", f"Could not open unvaulted directory: {e}")


    def update_file_list(self):
        # Clear previous widgets
        for widget in self.frame.winfo_children():
            widget.destroy()

        # List files in the vault
        files = os.listdir(vault_dir)
        for file in files:
            row = ctk.CTkFrame(self.frame)
            row.pack(pady=5, padx=10, fill="x")

            # File name label (wrap text for long filenames)
            file_label = ctk.CTkLabel(row, text=file, width=220, anchor="w", font=("Arial", 12), wraplength=200)  # Allow wrapping
            file_label.pack(side="left", padx=5, fill="x", expand=True)

            # View button
            view_button = ctk.CTkButton(row, text="👁 View", width=80, command=lambda f=file: self.view_file_location(f), font=("Arial", 12))
            view_button.pack(side="left", padx=5)

            # Decrypt button
            decrypt_button = ctk.CTkButton(row, text="⬇ Decrypt", width=100, command=lambda f=file: self.select_file(f), font=("Arial", 12))
            decrypt_button.pack(side="left", padx=5)

            # Delete button
            delete_button = ctk.CTkButton(row, text="🗑 Delete", width=80, command=lambda f=file: self.delete_file(f), font=("Arial", 12))
            delete_button.pack(side="left", padx=5)


    def select_file(self, file_name):
        encrypted_file_path = os.path.join(vault_dir, file_name)
        try:
            decrypt_file(encrypted_file_path, self.password)
            messagebox.showinfo("Success", f"File retrieved and saved as {file_name[:-4]}")
        except Exception as e:
            messagebox.showerror("Error", f"Wrong password for specified file!")

    def add_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                encrypt_file(file_path, self.password)
                self.update_file_list()
                messagebox.showinfo("Success", "File added successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add file: {e}")

    def delete_file(self, file_name):
        encrypted_file_path = os.path.join(vault_dir, file_name)
        try:
            os.remove(encrypted_file_path)
            self.update_file_list()
            messagebox.showinfo("Success", f"File {file_name} deleted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete file: {e}")

# Start
if __name__ == "__main__":
    root = ctk.CTk()
    app = FileCabinetApp(root)
    root.mainloop()

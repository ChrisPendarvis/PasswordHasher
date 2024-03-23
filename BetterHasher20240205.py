import tkinter as tk
from tkinter import ttk
#import bcrypt
from threading import Thread
import hashlib
from argon2 import PasswordHasher

from passlib.hash import bcrypt

class PasswordHashProgram:
    
    def __init__(self, root):
        self.root = root
        self.progress_var = tk.DoubleVar()
        self.create_widgets()
        
    def create_widgets(self):
        tk.Label(self.root, text="Enter Passwords (one per line):", bg='#292929', fg='white', font=('Courier', 12)).pack(pady=5)
        self.password_entry = tk.Text(self.root, height=5, width=30, bg='#484848', fg='white', insertbackground='white', font=('Courier', 12))
        self.password_entry.pack(pady=5)
        
        # Bcrypt button, may change color
        tk.Button(self.root, text="Hash with bcrypt", command=self.hash_bcrypt, bg='#b71c1c', fg='white', font=('Courier', 12)).pack(pady=5)
        # Argon2 button, pain in ass
        tk.Button(self.root, text="Hash with Argon2", command=self.hash_argon2, bg='#1c4587', fg='white', font=('Courier', 12)).pack(pady=5)
        # SHA button, we're sticking to 256
        tk.Button(self.root, text="Hash with SHA-256", command=self.hash_sha256, bg='#006400', fg='white', font=('Courier', 12)).pack(pady=5)
        
        self.result_label = tk.Label(root, text="", bg='#292929', fg='white', font=('Courier', 12))
        self.result_label.pack(pady=10)

        tk.Button(self.root, text="Copy to Clipboard", command=self.copy_to_clipboard, bg='#006064', fg='white', font=('Courier', 12)).pack(pady=10)
        
        self.copied_label = tk.Label(self.root, text="", bg='#292929', fg='white', font=('Courier', 12))
        self.copied_label.pack(pady=10)

        self.error_label = tk.Label(self.root, text="", bg='#292929', fg='red', font=('Courier', 12))
        self.error_label.pack(pady=10)
        
        
    def hash_bcrypt(self): # gensalt() takes an optional parameter 'rounds'. Ex. gensalt(rounds=8)
        passwords = self.password_entry.get("1.0", "end-1c").splitlines()
        hashed_passwords = [bcrypt.using(rounds = 12, ident = "2a").hash(password) for password in passwords if password.strip()]
        #hashed_passwords = [bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8') for password in passwords if password.strip()] - Switched to passlib bcrypt instead of bcrypt
        result_text = "\n".join(hashed_passwords)
        self.display_hashes(result_text)

    def hash_argon2(self): # Argon is Argon
        passwords = self.password_entry.get("1.0", "end-1c").splitlines()
        ph = PasswordHasher()
        hashed_passwords = [ph.hash(password) for password in passwords if password.strip()]
        result_text = "\n".join(hashed_passwords)
        self.display_hashes(result_text)

    def hash_sha256(self): # SHA-516 and 384 aren't worth it :[
        passwords = self.password_entry.get("1.0", "end-1c").splitlines()
        hashed_passwords = [hashlib.new("sha256", password.encode('utf-8')).hexdigest() for password in passwords if password.strip()]
        result_text = "\n".join(hashed_passwords)
        self.display_hashes(result_text)
        
    def hash(self, password): # For Argon
        ph = PasswordHashProgram()
        hashed_password = ph.hash(password)
        return hashed_password
    
    def worker(self, algorithm, non_empty_passwords):
        try:
            self.loading_window.start()

            if algorithm == "bcrypt":
                result_text = self.hash_bcrypt(non_empty_passwords)
            elif algorithm == "argon2":
                result_text = self.hash_argon2(non_empty_passwords)
            elif algorithm == "sha256":
                result_text = self.hash_sha256(non_empty_passwords)
            else:
                result_text = "Unsupported algorithm :["
            
        except Exception as e:
            result_text = f"Error: {str(e)}"
                
        finally:
            self.loading_window.stop()
            self.root.after(0, lambda: self.display_hashes(result_text))
            
    def display_hashes(self, result_text):
        hashed_passwords = result_text.split("\n")

        displayed_hashes = "\n".join(hashed_passwords[:15]) # Only shows first 15 passwords on screen

        if len(hashed_passwords) > 15:
            displayed_hashes += f"\n... and more ({len(hashed_passwords) - 15} hidden!)"

        self.result_label.config(text=displayed_hashes)
        self.full_result_text = result_text
        #result_text = None
    # def display_hashes(self, result_text):
    #     max_display = 15
    #     hashed_passwords = result_text.split("\n")
    #     if len(hashed_passwords) > max_display:
    #         displayed_hashes = hashed_passwords[:max_display] + ['...and more!']
    #     else:
    #         displayed_hashes = result_text
        
    #     self.result_label.config(text="\n".join(displayed_hashes))
    
    
    def copy_to_clipboard(self):
        try:
            self.root.clipboard_clear() # Might add this again but who wants their clipboard cleared?
            #3/23/24 - Added again because copy button would append the previously hashed values onto the new copy.
            self.root.clipboard_append(self.full_result_text)
            self.root.update()

            self.copied_label.config(text="Copied to Clipboard! :]")
            self.root.after(2000, lambda: self.copied_label.config(text=""))
            #self.full_result_text = None

        except Exception as e:
            self.error_label.config(text=f"Error: {str(e)}")

    def update_progress(self): # Will this ever work?
        value = self.progress_var.get() + 2 #   +1 was too slow, +5 is too fast
        if value > 100:
            value = 0
            self.progress_var.set(value)
        self.loading_window.after(10, self.update_progress)
            
    def hash_or_encrypt(self, algorithm):
        passwords = self.password_entry.get("1.0", "end-1c").splitlines()
        
        non_empty_passwords = [password for password in passwords if password.strip()] # To prevent empty strings from being hashed
        if not non_empty_passwords:
            self.result_label.config(text="")
            self.error_label.config(text="Error: Please enter password...")
            self.loading_window.destroy()
            root.after(2000, lambda: self.error_label.config(text=""))
            return
        
        self.loading_frame = ttk.Frame(self.root) # Doesn't work but it's okay
        self.loading_window = ttk.Progressbar(self.loading_frame, orient='horizontal', mode='indeterminate', variable=self.progress_var, length=200, style='TProgress.Horizontal.TProgressbar')
        self.loading_window.pack(padx=20, pady=10)
        self.loading_frame.pack(pady=10)

        Thread(target=self.worker, args=(algorithm, non_empty_passwords)).start()
        self.update_progress()

root = tk.Tk()
root.title("Chris' Multi-Password Hashing Program")
root.configure(bg='#292929')

app = PasswordHashProgram(root)
root.mainloop()

# 2 praktine uzduotis: AES algoritmo sifravimo/desifravimo sistema
from tkinter import filedialog
from tkinter import messagebox
import tkinter as tk
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES

random_bytes = get_random_bytes(AES.block_size)

def get_message_input():
    message = message_input.get()
    return message

def get_key():
    key = key_entry.get()
    key_length = len(key.encode('utf-8'))
    if key_length not in [16, 24, 32]:
        messagebox.showinfo("Invalid Key Length",
                            "Invalid key length. AES-128 requires 16-byte key,\n"
                            "AES-192 requires 24-byte key, AES-256 requires 32-byte key.")
        return None
    return key

def save_to_file(data):
    file_path = filedialog.asksaveasfilename(defaultextension=".txt")
    if file_path:
        with open(file_path, "w") as file:
            file.write(data)
            messagebox.showinfo("Save Successful", "File saved successfully.")

def load_from_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, "r") as file:
            message = file.read()
            message_input.delete(0, tk.END)
            message_input.insert(tk.END, message)

# - - - ENCRYPTION FUNCTIONS - - -

def ECB_encryption():
    message = get_message_input()
    key = get_key()
    if key is None:
        return
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    encrypted_message = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, encrypted_message.hex())
    save_to_file(encrypted_message.hex())

def CBC_encryption():
    message = get_message_input()
    key = get_key()
    if key is None:
        return
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, random_bytes)
    encrypted_message = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, encrypted_message.hex())
    save_to_file(encrypted_message.hex())

def CFB_encryption():
    message = get_message_input()
    key = get_key()
    if key is None:
        return
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CFB, random_bytes)
    encrypted_message = cipher.encrypt(message.encode('utf-8'))
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, encrypted_message.hex())
    save_to_file(encrypted_message.hex())

# - - - DECRYPTION FUNCTIONS - - -

def ECB_decryption():
    message = get_message_input()
    key = get_key()
    if key is None:
        return
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    decrypted_message = unpad(cipher.decrypt(bytes.fromhex(message)), AES.block_size)
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, decrypted_message.decode('utf-8'))

def CBC_decryption():
    message = get_message_input()
    key = get_key()
    if key is None:
        return
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, random_bytes)
    decrypted_message = unpad(cipher.decrypt(bytes.fromhex(message)), AES.block_size)
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, decrypted_message.decode('utf-8'))

def CFB_decryption():
    message = get_message_input()
    key = get_key()
    if key is None:
        return
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CFB, random_bytes)
    decrypted_message = cipher.decrypt(bytes.fromhex(message))
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, decrypted_message.decode('utf-8'))


root = tk.Tk()
root.title("AES Encryption/Decryption Program")

text_label = tk.Label(root, text="Enter a message for encryption/decryption:")
text_label.pack()

message_input = tk.Entry(root)
message_input.pack()

key_label = tk.Label(root, text="Enter a key word for encryption/decryption:")
key_label.pack()

key_entry = tk.Entry(root)
key_entry.pack()

button_ecb_encrypt = tk.Button(root, text="ECB encryption", command=ECB_encryption)
button_ecb_encrypt.pack()

button_ecb_decrypt = tk.Button(root, text="ECB decryption", command=ECB_decryption)
button_ecb_decrypt.pack()

button_cbc_encrypt = tk.Button(root, text="CBC encryption", command=CBC_encryption)
button_cbc_encrypt.pack()

button_cbc_decrypt = tk.Button(root, text="CBC decryption", command=CBC_decryption)
button_cbc_decrypt.pack()

button_cfb_encrypt = tk.Button(root, text="CFB encryption", command=CFB_encryption)
button_cfb_encrypt.pack()

button_cfb_decrypt = tk.Button(root, text="CFB decryption", command=CFB_decryption)
button_cfb_decrypt.pack()

label_result = tk.Label(root, text="Result:")
label_result.pack()

result_text = tk.Text(root, height=1)
result_text.pack()

button_load_from_file = tk.Button(root, text="Load from a file", command=load_from_file)
button_load_from_file.pack()

root.mainloop()
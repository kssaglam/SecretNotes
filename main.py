import tkinter.filedialog
import tkinter.messagebox
from tkinter import *
from tkinter import messagebox
from PIL import Image, ImageTk
import base64
from cryptography.fernet import Fernet



window = Tk()
window.title("Secret Notes")
window.config(padx=20, pady=20)
window.minsize(width=500, height=700)

def encrypt_content():
    title = title_input.get()
    content = content_input.get("1.0",END)
    masterkey = masterkey_input.get()
    key = base64.b64encode(f"{masterkey:<32}".encode("utf-8"))
    f = Fernet(key)
    enc_content = f.encrypt(content.encode())
    if title == "" or len(content) == 1 or masterkey == "":
        messagebox.showerror(title="Error", message="Enter All Information")
    else:
        with open("Secret.txt",mode="a") as file:
            file.write("\n"+title+"\n")
        with open ("Secret.txt", mode="ab") as file:
            file.write(enc_content)

def decrypt_content():
    encrypted = content_input.get("1.0",END)
    masterkey = masterkey_input.get()
    key = base64.b64encode(f"{masterkey:<32}".encode("utf-8"))
    f = Fernet(key)
    try:
        dec_content = f.decrypt(encrypted)
        content_input.delete("1.0",END)
        content_input.insert("1.0",dec_content.decode())
    except:
        messagebox.showerror(title="Error", message="Enter The Correct Key")


image = Image.open("top-secret-stamp-png.png")
image = image.resize((80,100))
secret_image = ImageTk.PhotoImage(image)

image_label = Label(window, image=secret_image)
image_label.pack()

title_label = Label(text="Enter Your Title")
title_label.pack()

title_input = Entry(width=30)
title_input.pack()

content_label = Label(text="Enter Your Secret")
content_label.pack()

content_input = Text(width=70)
content_input.pack()

key_label = Label(text="Enter Master Key")
key_label.pack()

masterkey_input = Entry(width=30)
masterkey_input.pack()

save_button = Button(text="Save & Encrypt", command=encrypt_content)
save_button.pack()

decrypt_button = Button(text="Decrypt", command=decrypt_content)
decrypt_button.pack()








window.mainloop()
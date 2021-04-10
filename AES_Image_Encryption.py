from Crypto.Cipher import AES
from Crypto import Random
from Tkinter import *
import tkFileDialog
import tkMessageBox
import os
import PIL
from PIL import Image
import math
import hashlib
import binascii
import numpy as np
import imagehash


# iv = Random.new().read(AES.block_size)

extension = ".jpeg"
iv = "abcdefghijklmnop"

def hashing(filename):
	hash_value = imagehash.average_hash(Image.open(filename))
	filename = filename.split('.')
	filename = filename[0]
	filename = filename + ".hash"
	hash_file = open(filename, "w")
	hash_file.write(str(hash_value))
	hash_file.close()
	return filename
	
	
def read_hash():
	inp_hash_file = open(original_hash_file_name)
	inp_hash_data = inp_hash_file.read()
	inp_hash_file.close()
	dec_hash_file = open(decrypted_hash_file_name)
	dec_hash_data = dec_hash_file.read()
	dec_hash_file.close()
	if inp_hash_file == dec_hash_file:
		return True
	else:
		return False
	
 
def encrypt(filename, key):
	input_file = open(filename)
	input_data = input_file.read()
	input_file.close()
	cfb_cipher = AES.new(key, AES.MODE_CFB, iv)
	enc_data = cfb_cipher.encrypt(input_data)
	enc_filename = filename.split('.')
	enc_filename = enc_filename[0]
	enc_filename = enc_filename + ".crypt"
	enc_file = open(enc_filename, "w")
	enc_file.write(enc_data)
	enc_file.close()
	return enc_filename

def decrypt(filename,key):
	enc_file2 = open(filename)
	enc_data2 = enc_file2.read()
	enc_file2.close()
	cfb_decipher = AES.new(key, AES.MODE_CFB, iv)
	plain_data = cfb_decipher.decrypt(enc_data2)
	dec_filename = filename.split('.')
	dec_filename = dec_filename[0]
	dec_filename = dec_filename + "_decypt"+extension
	output_file = open(dec_filename, "w")
	output_file.write(plain_data)
	output_file.close()
	return dec_filename

def pass_alert():
   tkMessageBox.showinfo("Password Alert","Please enter a password.")

def enc_success(imagename,hashfile):
   tkMessageBox.showinfo("Success","\nEncrypted Image File : " + imagename + "\nOriginal Image Hash File : " + hashfile)
   
def dec_success(imagename,hashfile,flag):
   if flag:
   	tkMessageBox.showinfo("Success Image Integrity maintained","\nDecrypted Image File: "  		 	 +imagename+"\nDecrypted Image Hash File : " + hashfile)
   else:
   	tkMessageBox.showinfo("Image Integrity not maintained","\nDecrypted Image File: " + imagename+
   	"\nDecrypted Image Hash File : " + hashfile)

# image encrypt button event
def image_open():
    global file_path_e

    enc_pass = passg.get()
    if enc_pass == "":
        pass_alert()
    else:
        password = hashlib.sha256(enc_pass).digest()
        filename = tkFileDialog.askopenfilename()
        file_path_e = os.path.dirname(filename)
        hash_file_name = hashing(filename)
        enc_filename = encrypt(filename,password)
        enc_success(enc_filename,hash_file_name)

# image decrypt button event
def cipher_open():
    global file_path_d

    dec_pass = passg.get()
    if dec_pass == "":
        pass_alert()
    else:
        password = hashlib.sha256(dec_pass).digest()
        filename = tkFileDialog.askopenfilename()
        file_path_d = os.path.dirname(filename)
        dec_filename = decrypt(filename,password)
        global decrypted_hash_file_name
        global original_hash_file_name
        original_hash_file_name = filename.split(".")
        print(original_hash_file_name)
        original_hash_file_name = original_hash_file_name[0]+".hash"
        decrypted_hash_file_name = hashing(dec_filename)
        flag = read_hash()
        dec_success(dec_filename,decrypted_hash_file_name,flag)	
        
        	


class App:
  def __init__(self, master):
    global passg
    title = "AES Image Encryption"
    author = "Sahil Gupta : 1805692\nSujoya Datta : 1805714\nSahil Pandey : 1805330"
    msgtitle = Message(master, text =title)
    msgtitle.config(font=('helvetica', 20, 'bold'), width=300)
    msgauthor = Message(master, text=author)
    msgauthor.config(font=('helvetica',15), width=300)

    canvas_width = 600
    canvas_height = 150
    w = Canvas(master,
           width=canvas_width,
           height=canvas_height)
    msgtitle.pack()
    msgauthor.pack()
    w.pack()

    passlabel = Label(master, text="Enter Encrypt/Decrypt Password:")
    passlabel.pack()
    passg = Entry(master, show="*", width=20)
    passg.pack()
    self.encrypt = Button(master, text="Encrypt", fg="black", command=image_open, width=25,height=5)
    self.encrypt.pack(side=LEFT)
    self.decrypt = Button(master, text="Decrypt", fg="black", command=cipher_open, width=25,height=5)
    self.decrypt.pack(side=RIGHT)


# ------------------ MAIN -------------#
root = Tk()
root.wm_title("AES Image Encryption")
app = App(root)
root.mainloop()

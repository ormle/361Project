#===============================================================================
# Cmpt 361 Project
# Group Members: Legan, Mark, Romel
#===============================================================================
# Client application of secure mail transfer protocol
#===============================================================================
import socket, sys, json, os, glob, datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

def get_Server_key():
    '''
    Retrieves the public server key from the file 
    which each client machine has
    '''
    with open("server_public.pem", "rb") as serverKeyFile:
        server_key = serverKeyFile.read()
    return server_key

def get_client_priv_key(clientUser):
    '''
    Retrieves the clients private key from a file
    '''
    with open(clientUser + "_private.pem", "rb") as privateKeyFile:
        priv_key = privateKeyFile.read()
    return priv_key

def encrypt_RSA(message, key):
    '''
    Encrypts a message with RSA
    '''
    pubkey = RSA.import_key(key)
    cipher_rsa_en = PKCS1_OAEP.new(pubkey)
    enc_data = cipher_rsa_en.encrypt(message) 
    return enc_data

def decrypt_RSA(enc_msg, clientUser):
    '''
    Decrypts a message with RSA
    '''
    privkey = RSA.import_key(get_client_priv_key(clientUser))
    cipher_rsa_dec = PKCS1_OAEP.new(privkey)
    dec_data = cipher_rsa_dec.decrypt(enc_msg)
    #print(dec_data.decode('ascii'))    
    return dec_data

def encrypt_sym(message, cipher):
    '''
    Encrypts a message using the symmetric key
    '''
    enc_data = cipher.encrypt(pad(message.encode('ascii'), 16))
    return enc_data

def decrypt_sym(en_msg, cipher):
    '''
    Decrypts a message using the symmetric key
    '''
    padded_msg = cipher.decrypt(en_msg)
    #Remove padding
    data = unpad(padded_msg, 16)
    return data.decode('ascii')

def client():    
    # Server Information
    serverName = input("Enter the server IP or name: ")   
    serverPort = 13004
    
    #Create client socket that using IPv4 and TCP protocols 
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:',e)
        sys.exit(1)    
    
    try:
        #Client connect with the server
        clientSocket.connect((serverName,serverPort))
        
        #Ask user to enter their username and password
        username = input("Enter your username: ")
        password = input("Enter your password: ")
        
        userPass = username + " " + password
        #Encrypt both with server public key and send
        en_UserPass = encrypt_RSA(userPass.encode('ascii'), get_Server_key())
        
        #Client send encrypted userPass message to the server
        clientSocket.send(en_UserPass)
        
        
        #Client recieves USERNAME/PASS verification result from the server 
        authentication_response = clientSocket.recv(2048).decode('ascii')
        #print(authentication_response)

        # authentication response var tells us what to expect back based on login attempt
        # If the credentials were bad, expect to hear about it from the server w/ unecrypted msg
        # If good, expect to recieve the encrypted SYM KEY
        if authentication_response == "GOODCRED":            
            # receive SYM_KEY (RSA encrypted)
            sym_key = decrypt_RSA(clientSocket.recv(2048), username) 
            #print("SYMKEY: ", sym_key)
        else:
         # recieve a msg that we've entered the wrong credentials and then terminate
         print(clientSocket.recv(2048).decode('ascii'))
         clientSocket.close()  
         return 

        sym_cipher = AES.new(sym_key, AES.MODE_ECB) # prep cipher w/ symkey for use
        # while loop for the menu and client requests
        while True:            
            # collect choice from client
            menu_msg = decrypt_sym(clientSocket.recv(2048), sym_cipher)
            user_choice = input(menu_msg)
            # send choice over to server-side
            clientSocket.send(encrypt_sym(user_choice, sym_cipher))
            if user_choice == "1":
                pass
            if user_choice == "2":
                pass
            if user_choice == "3":
                pass
            if user_choice == "4":
                print("Terminating connection with the server.")
                break        
       
        # Client terminate connection with the server
        clientSocket.close()
        
    except socket.error as e:
        print('An error occured:',e)
        clientSocket.close()
        sys.exit(1)

#----------
client()

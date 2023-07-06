#===============================================================================
# Cmpt 361 Project
# Group Members: Legan, Mark, Romel
#===============================================================================
# Client application of secure mail transfer protocol
#===============================================================================
import socket, sys, json, os, glob, datetime
from Crypto.PublicKey import RSA
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
    enc_data = cipher_rsa_en.encrypt(message.encode('ascii')) 
    return enc_data

def decrypt_RSA(en_msg, clientUser):
    '''
    Decrypts a message with RSA
    '''
    privkey = RSA.import_key(get_client_priv_key(clientUser))
    cipher_rsa_dec = PKCS1_OAEP.new(privkey)
    dec_data = cipher_rsa_dec.decrypt(enc_msg)
    #print(dec_data.decode('ascii'))    
    return dec_data.decode('ascii')

def encrypt_sym(message, cipher):
    '''
    Encrypts a message using the symmetric key
    '''
    en_data = cipher.encrypt(pad(message.encode('ascoo'), 16))
    return enc_data

def decrypt_sym(en_msg, cipher):
    '''
    Decrypts a message using the symmetric key
    '''
    padded_msg = cipher.decrypt(en_msg)
    #Remove padding
    encoded_msg = unpad(padded_msg, 16)
    return enc_data.decode('ascii')

def client():
    IpName = input("Enter the server IP or name: ")
    
    # Server Information
    serverName = '127.0.0.1' #'localhost'
    serverPort = 13000
    
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
        password = input("Enter your password")
        
        userPass = username + " " + password
        #Encrypt both with server public key and send
        en_UserPass = encrypt_RSA(userPass, get_Server_key())
        
        #Client send encrypted userPass message to the server
        clientSocket.send(en_UserPass)
        
        # Client receives a message from the server and print it
        message = clientSocket.recv(2048)
        print(message.decode('ascii'))
        
        # Client terminate connection with the server
        clientSocket.close()
        
    except socket.error as e:
        print('An error occured:',e)
        clientSocket.close()
        sys.exit(1)

#----------
client()

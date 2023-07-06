#===============================================================================
# Cmpt 361 Project
# Group Members: Legan, Mark, Romel
#===============================================================================
# Server application of secure mail transfer protocol
#===============================================================================

import socket, sys, json, os, glob, datetime
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

def get_server_privateKey():
    '''
    Retrieves the private server key from a file
    '''
    with open("server_private.pem", "rb") as serverKeyFile:
        server_key = serverKeyFile.read()
    return server_key    

def make_symKey():
    '''
    Generates a 256 AES key to continue server-client communication
    '''
    #Generate Key
    keyLen = 256
    sym_key = get_random_bytes(int(keyLen/8))
    
    return sym_key

def encrypt_RSA(message, key):
    '''
    Encrypts a message with RSA
    '''
    pubkey = RSA.import_key(key)
    cipher_rsa_en = PKCS1_OAEP.new(pubkey)
    enc_data = cipher_rsa_en.encrypt(message.encode('ascii')) 
    return enc_data

def decrypt_RSA(en_msg):
    '''
    Decrypts a message with RSA
    '''
    privkey = RSA.import_key(get_server_privateKey())
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

def server():
    #Server port
    serverPort = 13000
    
    #Create server socket that uses IPv4 and TCP protocols 
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in server socket creation:',e)
        sys.exit(1)
    
    #Associate 12000 port number to the server socket
    try:
        serverSocket.bind(('', serverPort))
    except socket.error as e:
        print('Error in server socket binding:',e)
        sys.exit(1)        
        
    print('The server is ready to accept connections')
        
    #The server can only have one connection in its queue waiting for acceptance
    serverSocket.listen(5)
        
    while 1:
        try:
            #Server accepts client connection
            connectionSocket, addr = serverSocket.accept()
            print(addr,'   ',connectionSocket)
            pid = os.fork()
            
            # If it is a client process
            if  pid== 0:
                
                serverSocket.close() 
                
                #Receive encrypted username and password
                en_userPass = connectionSocket.recv(2048)
                
                #Decrypt username and password
                userPass = decrypt_RSA(userPass)
                clientUser, clientPass = userPass.split(' ')
                
                #Check if username and password are valid
                #TODO - Need to creat JSON file to match
                #
                
                
                # if match
                #sym_key = make_symKey();
                #print("Connection Accepted and Symmetric Key Generated for client: ", clientUser)
                
                #else:
                #connectionSocket.send("Invalid Username or password")
                #print("The received client information: ", clientUser, " is invalid (Connection Terminated)")
                connectionSocket.close()
                
                return
            
            #Parent doesn't need this connection
            connectionSocket.close()
            
        except socket.error as e:
            print('An error occured:',e)
            serverSocket.close() 
            sys.exit(1)        
        except:
            print('Goodbye')
            serverSocket.close() 
            sys.exit(0)
            
        
#-------
server()

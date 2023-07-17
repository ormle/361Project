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

    
def get_content(client):
	'''
	This function creates the content in the email
	The user can load a text file or type themselves
	'''
	load = input("Would you like to load contents from a file?(Y/N): ")
	if load == "Y":
		folder = "./" + client
		file_name = input("Enter filename: ")
		#Get the file from the users folder
		full_name = os.path.join(folder, file_name)
		
		f = open(full_name, "r")
		e_content = f.read()
		f.close()
	else:
		e_content = input("Enter message contents: ")
	return e_content
    
def make_email(client):
	'''
	This function makes the email list
	It call on another function to get the content
	'''
	e_to = input("Enter destinations (seperated by ;): ")
	e_title = input("Enter title: ")
	while len(e_title) > 99:
		e_title = input("Title too long. Try again: ")
	e_content = get_content(client)
	while len(e_content) > 999999:
		print("Email content too long. Try Again")
		e_content = get_content(client)
	length = len(e_content)
	email = [e_to, e_title, str(length), e_content]
	return email


def encrypt_sym_raw(message, cipher):
    '''
    Encrypts a message using the symmetric key ** no ascii encoding
    '''
    enc_data = cipher.encrypt(pad(message, 16))
    return enc_data

def decrypt_sym_raw(en_msg, cipher):
    '''
    Decrypts a message using the symmetric key ** no ascii encoding 
    '''
    padded_msg = cipher.decrypt(en_msg)
    #Remove padding
    data = unpad(padded_msg, 16)
    return data
	


def client():    
    # Server Information
    serverName = input("Enter the server IP or name: ")   
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

                #Receive the ok message
                ok_message = decrypt_sym(clientSocket.recv(2048), sym_cipher)
                #Start making the email
                email_list = make_email(username)
                #Get and send the From
                e_from = username
                clientSocket.send(encrypt_sym(e_from, sym_cipher))
                ok_message = decrypt_sym(clientSocket.recv(2048), sym_cipher)
                #Loop through email list to send rest of email
                for x in email_list:
                    print(x)
                    clientSocket.send(encrypt_sym(x, sym_cipher))
                    ok_message = decrypt_sym(clientSocket.recv(2048), sym_cipher)

            if user_choice == "2":
                pass
            if user_choice == "3":
                # View email protocol 
                # Receive index msg + index range
                index_msg = clientSocket.recv(2048)
                index_msg = decrypt_sym(index_msg, sym_cipher)
                index_msg, index_range = index_msg.split(";")
                #print(index_msg, index_range)
                # Check if inbox empty
                if int(index_range) == 0:
                    print("Inbox is empty. Returning to main menu.")
                    continue
                # Inbox non-empty, get index from client && check if its valid
                while True: 
                    index_choice = input("Enter the email index you wish to view: ")
                    if int(index_choice) <= int(index_range) and (int(index_choice) >= 0):
                        break
                # Send index choice back
                clientSocket.send(encrypt_sym(index_choice, sym_cipher))                

                # recieve the file size
                en_file_sz = decrypt_sym(clientSocket.recv(2048), sym_cipher)
                print(en_file_sz)    
                # send ok msg
                clientSocket.send(encrypt_sym("ok",sym_cipher))          


                # Note: this following loop was adapted from this example at
                # https://geekyhumans.com/encrypted-file-transfer-via-sockets-in-python/
                # Receive email as encrypted byte chunks from server-side
                print("Beginning file transfer...")
                f_bytes = b""                
                while len(f_bytes) < int(en_file_sz):                     
                    f_bytes += clientSocket.recv(4096)
                    
                
                print("Encrypted File transmitted..")
                pad_bytes = sym_cipher.decrypt(f_bytes)
                bytes = unpad(pad_bytes, 16)
                print(str(bytes, 'ascii'))              
                           
                # send ok msg
                clientSocket.send(encrypt_sym("ok",sym_cipher))        
                
                
                     
                      
        
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

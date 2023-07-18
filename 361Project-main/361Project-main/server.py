#===============================================================================
# Cmpt 361 Project
# Group Members: Legan, Mark, Romel
#===============================================================================
# Server application of secure mail transfer protocol
#===============================================================================

import socket, sys, json, os, glob, datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

def get_server_privateKey():
    '''
    Retrieves the private server key from a file
    '''
    with open("server_private.pem", "rb") as serverKeyFile:
        server_key = serverKeyFile.read()
    return server_key    


def get_client_pub_key(clientUser):
    '''
    Retrieves the clients public key from a file
    '''
    with open(clientUser + "_public.pem", "rb") as publicKeyFile:
        pub_key = publicKeyFile.read()
    return pub_key

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
    enc_data = cipher_rsa_en.encrypt(message) 
    return enc_data

def decrypt_RSA(enc_msg):
    '''
    Decrypts a message with RSA
    '''
    privkey = RSA.import_key(get_server_privateKey())
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

    
def save_email(email, title, to):
	'''
	This function saves the email as a text file into each 
	of the clients folders
	'''
	to_list = list(to.split(";"))
	for x in to_list:
		save = "./" + x
		file_name = title + ".txt"
		#Get the folder we need to save into
		full_name = os.path.join(save, file_name)
		file1 = open(full_name, "w")
		file1.write(email)
		file1.close()
	return
	
def get_json(client):
	'''
	This function loads the json information into a dictionary
	Opens the folder of the client requested
	'''
	folder = "./" + client
	file_name = client + "_Dict.json"
	full_name = os.path.join(folder, file_name)
	j = open(full_name)
	json_data = json.load(j)
	j.close()
	return json_data
	
def save_json(client, data_list):
	'''
	This function updates the json dictionary of each of the client
	that receive the email
	'''
	to_list = list(client.split(";"))
	for x in to_list:
		#Get the dictionary
		json_data = get_json(x)
		#Add a new index
		index = len(json_data)
		json_data[index+1] = data_list
		#Add the new dictionary into a json object
		json_object = json.dumps(json_data, indent = 4)
		#Get the json file from the folder of the client
		folder = "./" + x
		file_name = x + "_Dict.json"
		full_name = os.path.join(folder, file_name)
		#Update the json file
		with open(full_name, "w") as outfile:
			outfile.write(json_object)


def server():
    #Server port
    serverPort = 13004
    
    json_dict = {}
    
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
                userPass = decrypt_RSA(en_userPass).decode('ascii')
                clientUser, clientPass = userPass.split(' ')
                print(clientUser, clientPass)
                
                
                
                
                #Check if username and password are valid 
                with open("user_pass.json", "r") as read_file:
                    data = json.load(read_file)
                    
                    # Respond to corect or incorrect credentials
                    credential_match = False
                    if clientUser in data:
                        stored_pass = data[clientUser] 
                        if stored_pass == clientPass:
                            print("Connection Accepted and Symmetric Key Generated for client: ", clientUser)
                            authentication_response = "GOODCRED"
                            credential_match = True
                            connectionSocket.send(authentication_response.encode('ascii'))
                    else:
                        authentication_response = "BADCRED"        
                        connectionSocket.send(authentication_response.encode('ascii'))
                        print("The received client information: ", clientUser, " is invalid (Connection Terminated)")
                

                
                if credential_match:
                    # gen symkey, encrypt RSA and send
                    sym_key = make_symKey()
                    en_sym_key = encrypt_RSA(sym_key, get_client_pub_key(clientUser))
                    connectionSocket.send(en_sym_key)
                    pass

                else:
                    connectionSocket.send("Invalid username or password.\nTerminating.".encode('ascii'))
                    connectionSocket.close()
                    return               
                
                sym_cipher = AES.new(sym_key, AES.MODE_ECB) # prep cipher w/ symkey for use
                # while loop for the menu and client requests
                while True:

                    menu_msg = '''Select the operation:
    1) Create and send an email
    2) Display the inbox list
    3) Display the email contents
    4) Terminate the connection
    choice: '''
                    # Encrypt the menu and send it to the client side
                    en_menu_msg = encrypt_sym(menu_msg, sym_cipher)
                    connectionSocket.send(en_menu_msg)

                    # Receive choice and act accordingly
                    user_choice = decrypt_sym(connectionSocket.recv(2048), sym_cipher)
                    print("Users choice was: " + user_choice)
                    if user_choice == "1":

                    	#Send ok message
                    	ok_message = encrypt_sym("Send the email", sym_cipher)
                    	connectionSocket.send(ok_message)
                    	
                    	content_size = decrypt_sym(connectionSocket.recv(2048), sym_cipher)
                    	
                    	email_list = []
                    	#Receive the email information
                    	for x in range(5):
                    		if x == 5:
                    			while content_size > 0 & x == 5:
                    				info = decrypt_sym(connectionSocket.recv(2048), sym_cipher)
                    				print(info)
                    				email_list[x] = email_list[x] + info
                    				#send ok message
                    				ok_message = encrypt_sym("ok", sym_cipher)
                    				connectionSocket.send(ok_message)
                    		else:
                    			
                    			info = decrypt_sym(connectionSocket.recv(2048), sym_cipher)
                    			print(info)
                    			email_list.append(info)
                    			#send ok message
                    			ok_message = encrypt_sym("ok", sym_cipher)
                    			connectionSocket.send(ok_message)
                    	#Get time and date information
                    	time = datetime.datetime.now()
                    	date = time.strftime("%Y-%m-%d %H:%M:%S")
                    	#Save email information
                    	From = email_list[0]
                    	To = email_list[1]
                    	Title = email_list[2]
                    	length = email_list[3]
                    	content = email_list[4]
                    	email = "From: " + From + "\nTo: " + To + "\nTime and Date: " + date + "\nTitle: " + Title + "\nContent Length: " + length + "\nContent:\n" + content + "\n"
                    	#Save the email
                    	save_email(email, Title, To)
                    	#Update the json dictionary for each client
                    	data_list = [From, date, Title]
                    	save_json(To, data_list)
                    	

                    if user_choice == "2":
                        pass
                    if user_choice == "3":
                        pass
                    if user_choice == "4":
                        print("Connection terminated with " + clientUser + ".")
                        break
                             
                connectionSocket.close()                
                return
            
            #Parent doesn't need this connection
            connectionSocket.close()
            
        except socket.error as e:
            print('An error occured:',e)
            serverSocket.close() 
            sys.exit(1)        
        except Exception as e:
            print(e)
            serverSocket.close() 
            sys.exit(0)
            
        
#-------
server()

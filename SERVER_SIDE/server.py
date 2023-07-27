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
    serverPort = 13000
    
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
            #print(addr,'   ',connectionSocket)
            pid = os.fork()
            
            # If it is a client process
            if  pid== 0:
                
                serverSocket.close() 
                
                #Receive encrypted username and password
                en_userPass = connectionSocket.recv(2048)
                
                #Decrypt username and password
                userPass = decrypt_RSA(en_userPass).decode('ascii')
                clientUser, clientPass = userPass.split(' ')
                #print(clientUser, clientPass)               
                
                
                
                #Check if username and password are valid 
                with open("user_pass.json", "r") as read_file:
                    data = json.load(read_file)
                    
                    # Respond to corect or incorrect credentials
                    credential_match = False
                    if clientUser in data: # username check
                        stored_pass = data[clientUser] 
                        if stored_pass == clientPass: # password check
                            print("Connection Accepted and Symmetric Key Generated for client: ", clientUser)
                            authentication_response = "GOODCRED"
                            credential_match = True
                            connectionSocket.send(authentication_response.encode('ascii'))
                        else:
                            authentication_response = "BADCRED"        
                            connectionSocket.send(authentication_response.encode('ascii'))
                            print("The received client information: ", clientUser, " is invalid (Connection Terminated)")
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
                    #print("Users menu choice was: " + user_choice)
                    if user_choice == "1":

                        #Send ok message
                        ok_message = encrypt_sym("Send the email", sym_cipher)
                        connectionSocket.send(ok_message)
                        

                        content_size = int(decrypt_sym(connectionSocket.recv(2048), sym_cipher))
                        #print("Content size: ", content_size)
                        connectionSocket.send(ok_message)
                        
                        email_list = []
                        #Receive the email information
                        for x in range(5):
                            if x == 4:
                                data = connectionSocket.recv(2048)
                                ok_message = encrypt_sym("ok", sym_cipher)
                                connectionSocket.send(ok_message)
                                #print("getting content")
                                while len(data) < content_size:
                                    #print("In loop")
                                    info = connectionSocket.recv(2048)
                                    data = data + info
                                    #send ok message
                                    #ok_message = encrypt_sym("ok", sym_cipher)
                                    #connectionSocket.send(ok_message)
                                data = decrypt_sym(data, sym_cipher)
                                email_list.append(data)
                            else:
                                #print("In else")
                                info = decrypt_sym(connectionSocket.recv(2048), sym_cipher)
                                #print(info)
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
                        print("An email from " + From + " is sent to " + To + " has a content length of " + length + " .")
                        

                    if user_choice == "2":
                        #Display inbox list
                        client_dict = get_json(clientUser)
                        n_index = len(client_dict)
                        
                        #Send index range
                        index_msg = encrypt_sym("Server request;" + str(n_index), sym_cipher)
                        connectionSocket.send(index_msg)

                        #Receive ok message
                        ok_msg = decrypt_sym(connectionSocket.recv(2048), sym_cipher)
                        #print(ok_msg)

                        if n_index == 0: #Empty inbox, return to menu
                            continue
                        
                        #Otherwise at least one email in inbox
                        inbox_list = "Index\tFrom\t\tDatetime\t\t\tTitle\n"
                        #print(inbox_list)
                        for index in range(n_index):
                            i = str(index+1)
                            sender = client_dict[i][0]
                            #print('Sender: ', sender)
                            date = client_dict[i][1]
                            #print('Date: ', date)
                            email_title = client_dict[i][2]
                            #print('Title: ', email_title)

                            inbox_list += i + "\t" + sender + '\t\t' + date + '\t\t' + email_title + '\n'
                        
                        #print(inbox_list)
                        #Send inbox
                        inbox_list = encrypt_sym(inbox_list, sym_cipher)
                        connectionSocket.send(inbox_list)

                        #Receive ok message
                        ok_msg = decrypt_sym(connectionSocket.recv(2048), sym_cipher)
                        #print(ok_msg)

                    if user_choice == "3":
                        # View email protocol --

                        # Retrieve the email index range from client dict
                        client_dict = get_json(clientUser)
                        n_index = len(client_dict)
                        
                        # Ask the user for their index choice
                        # Also send the email index range for input check on client side
                        index_msg = encrypt_sym("the server request email index;" + str(n_index), sym_cipher)
                        connectionSocket.send(index_msg)

                        if n_index == 0: # inbox empty return to menu
                             continue
                        
                        # Receive index choice back 
                        index_choice = decrypt_sym(connectionSocket.recv(2048), sym_cipher)
                        #print("User index choice was: " + index_choice)
                        # Retrieve the file based on index from client JSON
                        email_name = client_dict[index_choice][2]
                        #print("email chosen: " + email_name + ".txt")

                        # Send file size to the client-side             
                        #f_sz = os.path.getsize(os.path.join(clientUser, email_name + ".txt"))
                        
                        
                        # Open text file, send encrypted bytes to client
                        with open(os.path.join(clientUser, email_name + ".txt"), 'rb') as f:
                            chunk = f.read()
                            pad_chunk = pad(chunk, 16)
                            en_chunk = sym_cipher.encrypt(pad_chunk)
                            en_file_sz = str(len(en_chunk))

                            connectionSocket.send(encrypt_sym(en_file_sz, sym_cipher))
                            ok_msg = connectionSocket.recv(2048)
                            connectionSocket.sendall(en_chunk)
                        ok_msg = connectionSocket.recv(2048) # Recieve ok message  
                                             
                                        
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

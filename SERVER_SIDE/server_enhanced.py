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
from Crypto.Random.random import getrandbits
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

def encrypt_sym(message, cipher, nonces=""):
    '''
    Encrypts a message using the symmetric key
    Adds nonces to the message
    '''
    message += nonces
    enc_data = cipher.encrypt(pad(message.encode('ascii'), 16))
    return enc_data

def decrypt_sym(en_msg, cipher, s_nonce, c_nonce):
    '''
    Decrypts a message using the symmetric key
    '''
    padded_msg = cipher.decrypt(en_msg)
    #Remove padding
    data = unpad(padded_msg, 16)
    data = data.decode('ascii')
    # Make sure nonces are part of the message
    if s_nonce in data and c_nonce in data:
        #Validate nonces
        if validate_nonce(s_nonce, c_nonce) == False:
            n_valid = False
        else:
            n_valid = True
        #Return message and validity
        return data.split(s_nonce)[0], n_valid
    #If for whatever reason there are no nonces, return decoded data
    return data

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
                        
def make_nonce():
    '''
    Creates a nonce, an random number which validates
    the client-server communication and prevents 
    playbacks
    '''
    nonce = getrandbits(128)
    return str(nonce)

def save_nonces(s_nonce, c_nonce):
    '''
    Updates the json file which holds the used nonces
    '''
    with open("nonces.json", 'r') as outfile:
        used_nonces = json.load(outfile)
    
    used_nonces.append(s_nonce)
    used_nonces.append(c_nonce)

    with open("nonces.json", 'w') as outfile:
        json_object = json.dumps(used_nonces)
        outfile.write(json_object)

def validate_nonce(s_nonce = '', c_nonce = ''):
    '''
    Checks the integrity of the message
    '''
    with open("nonces.json", 'r') as outfile:
        used_nonces = json.load(outfile)
        
        if s_nonce in used_nonces or c_nonce in used_nonces:
            return False
        else:
            return True

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

                #Receive username
                en_username = connectionSocket.recv(2048)
                #Decrypt username
                clientUser = decrypt_RSA(en_username).decode('ascii')
                print("Received username: ", clientUser)

                #Send server nonce
                s_nonce = make_nonce()
                #print("Server nonce: ", s_nonce, "Type: ", type(s_nonce))
                en_s_nonce = encrypt_RSA(s_nonce.encode('ascii'), get_client_pub_key(clientUser))
                connectionSocket.send(en_s_nonce)

                #Receive encrypted password + nonces
                en_pass_nonces = connectionSocket.recv(2048)
                
                #Decrypt password + nonces
                password_nonces = decrypt_RSA(en_pass_nonces).decode('ascii')
                #Split password from nonces
                #Split from s_nonce since we already know s_nonce
                clientPass, c_nonce = password_nonces.split(s_nonce)
                #print(clientUser, clientPass)
                print(clientUser + " Session Server nonce: ", s_nonce, "\nClient nonce: ", c_nonce)               
                
                #Check if nonces have been used before
                if validate_nonce(s_nonce, c_nonce) == False:
                    print("Repeated nonce(s) detected. Terminating sessions")                           
                    connectionSocket.close()
                    return
                #To keep track validity of nonces
                n_valid = True

                #Combine nonces together to include in future messages
                nonces = s_nonce + c_nonce

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
                    # gen symkey, add nonces, encrypt RSA and send
                    sym_key = make_symKey()
                    #Make nonces into byte to be able to add to sym_key
                    nonces_byte = nonces.encode("utf-8")
                    #Combine sym_key and nonces
                    #print("sym_key", sym_key, "\nnonces: ", nonces_byte)
                    combined_data = sym_key + nonces_byte
                    #print("combined: ", combined_data, "length: ", len(combined_data))
                    #Encrypt combined data
                    en_sym_key = encrypt_RSA(combined_data, get_client_pub_key(clientUser))
                    connectionSocket.send(en_sym_key)
                    pass

                else:
                    connectionSocket.send("Invalid username or password.\nTerminating.".encode('ascii'))
                    connectionSocket.close()
                    return               
                
                sym_cipher = AES.new(sym_key, AES.MODE_ECB) # prep cipher w/ symkey for use
                # while loop for the menu and client requests

                



                while True and n_valid:

                    menu_msg = '''Select the operation:
    1) Create and send an email
    2) Display the inbox list
    3) Display the email contents
    4) Terminate the connection
    choice: '''

                    # Encrypt the menu and send it to the client side
                    en_menu_msg = encrypt_sym(menu_msg, sym_cipher, nonces)
                    connectionSocket.send(en_menu_msg)

                    # Receive choice and act accordingly
                    user_choice, n_valid = decrypt_sym(connectionSocket.recv(2048), sym_cipher, s_nonce, c_nonce)
                    if n_valid:
                        print(clientUser + ": No nonce abnormalities detected. User menu choice recieved.")
                    
                    #print("Users menu choice was: " + user_choice)
                    if user_choice == "1":

                        #Send ok message
                        ok_message = encrypt_sym("Send the email", sym_cipher, nonces)
                        connectionSocket.send(ok_message)
                        
                        combined_content = decrypt_sym(connectionSocket.recv(2048), sym_cipher, s_nonce, c_nonce)
                        content_size = int(combined_content[0])
                        n_valid = combined_content[1]
                        
                        #print("Content size: ", content_size)
                        connectionSocket.send(ok_message)
                        
                        email_list = []
                        #Receive the email information
                        for x in range(5):
                            if x == 4:
                                data = connectionSocket.recv(2048)
                                ok_message = encrypt_sym("ok", sym_cipher, nonces)
                                connectionSocket.send(ok_message)
                                #print("getting content")
                                while len(data) < content_size:
                                    #print("In loop")
                                    info = connectionSocket.recv(2048)
                                    data = data + info
                                    #send ok message
                                    #ok_message = encrypt_sym("ok", sym_cipher)
                                    #connectionSocket.send(ok_message)
                                data, n_valid = decrypt_sym(data, sym_cipher, s_nonce, c_nonce)
                                email_list.append(data)
                            else:
                                #print("In else")
                                info, n_valid = decrypt_sym(connectionSocket.recv(2048), sym_cipher, s_nonce, c_nonce)
                                #print(info)
                                email_list.append(info)
                                #send ok message
                                ok_message = encrypt_sym("ok", sym_cipher, nonces)
                                connectionSocket.send(ok_message)
                        
                        # nonce integrity check
                        if n_valid:
                            print(clientUser + ": nonces_valid at email sending: ", n_valid)
                        else:
                            break

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

                        #ok_msg, n_valid = decrypt_sym(connectionSocket.recv(2048), sym_cipher, s_nonce, c_nonce)
                        
                        print("An email from " + From + " is sent to " + To + " has a content length of " + length + " .")
                        

                    if user_choice == "2":
                        #Display inbox list
                        client_dict = get_json(clientUser)
                        n_index = len(client_dict)
                        
                        #Send index range
                        index_msg = encrypt_sym("Server request;" + str(n_index), sym_cipher, nonces)
                        connectionSocket.send(index_msg)

                        #Receive ok message
                        ok_msg, n_valid = decrypt_sym(connectionSocket.recv(2048), sym_cipher, s_nonce, c_nonce)
                        #print(ok_msg)

                        if n_valid:
                            print(clientUser + " : requests inbox and recieved nonces still valid")
                        else:
                            break

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
                        inbox_list = encrypt_sym(inbox_list, sym_cipher, nonces)
                        connectionSocket.send(inbox_list)

                        #Receive ok message
                        ok_msg, n_valid = decrypt_sym(connectionSocket.recv(2048), sym_cipher, s_nonce, c_nonce)
                        #print(ok_msg)

                    if user_choice == "3":
                        # View email protocol --

                        # Retrieve the email index range from client dict
                        client_dict = get_json(clientUser)
                        n_index = len(client_dict)
                        
                        # Ask the user for their index choice
                        # Also send the email index range for input check on client side
                        index_msg = encrypt_sym("the server request email index;" + str(n_index), sym_cipher, nonces)
                        connectionSocket.send(index_msg)

                        if n_index == 0: # inbox empty return to menu
                             continue
                        
                        # Receive index choice back 
                        index_choice, n_valid = decrypt_sym(connectionSocket.recv(2048), sym_cipher, s_nonce, c_nonce)

                        if n_valid:
                            print(clientUser + " : User requests email and recieved nonces still valid")
                        else:
                            break
                
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

                if not n_valid:
                    print("Nonce Replay detected. Connection aborted.")             
                    connectionSocket.close()    
                    return

                save_nonces(s_nonce, c_nonce)
                print("Session nonces saved to the database")             
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

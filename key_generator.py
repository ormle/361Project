#===============================================================================
# Cmpt 361 Project
# Group Members: Legan, Mark, Romel
#===============================================================================
# Generates the public and private keys for the clients, and server applications
#===============================================================================
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

#Creates a public key for the client
def make_Client_Keys(clientUser):
    '''
    Creates a clients private and public keys and saves them
    individually onto files
    '''
    key = RSA.generate(2048)
    privateKey = key.export_key()
    publicKey = key.publickey.export_key()
    
    #Write keys to respective files
    with open(clientUser + "_private.pem", "wb") as privateKey_File:
        privateKey_File.write(privateKey)
        
    with open(clientUser + "_public.pem", "wb") as publicKey_File:
        publicKey_File.write(publicKey)
        
    
def make_Server_Keys():
    '''
    Creates the server machines private and public keys
    and saves them onto individual files
    '''
    key = RSA.generate(2048)
    privateKey = key.export_key()
    publicKey = key.publickey.export_key()
    
    #Write keys to respective files
    with open("server_private.pem", "wb") as privateKey_File:
        privateKey_File.write(privateKey)
        
    with open("server_public.pem", "wb") as publicKey_File:
        publicKey_File.write(publicKey)
        
#===============================================================================
make_Client_Keys("client1")
make_Client_Keys("client2")
make_Client_Keys("client3")
make_Client_Keys("client4")
make_Client_Keys("client5")
make_Server_Keys()

    

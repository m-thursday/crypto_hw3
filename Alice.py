from Crypto.Util.Padding import pad
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from base64 import b64encode
from base64 import b64decode
from sys import argv
import json
import Bob

#Generate AESKey
def generate_AESkey(block_size):
	#Set key
	aes_key = get_random_bytes(block_size)
	return aes_key
	
#Generate AESIV
def generate_AESiv(block_size):
	#Set IV
	aes_iv = get_random_bytes(block_size)
	return aes_iv
	
#AES encryption function
def aes_encrypt(plaintext, aes_key, aes_iv, block_size):
	
	#API implementation
	#Perform padding and encryption
	cipher_aes = AES.new(aes_key, AES.MODE_CBC, aes_iv)
	ciphertext = cipher_aes.encrypt(pad(plaintext,block_size))
	
	#JSON Formatting
	dictionary = {
		"head": "AES Encryption",
		"aes_key": b64encode(aes_key).decode('utf-8'),
		"aes_iv": b64encode(aes_iv).decode('utf-8'),
		"ciphertext": b64encode(ciphertext).decode('utf-8')
	}

	#Return JSON readable format
	return dictionary


def rsa_encrypt(plaintext):
	with open("rsa_key_data.json", 'r') as inFile:
		Obj = json.load(inFile)
		
	pub_key = RSA.import_key(b64decode(Obj['pub_key']))
		
	cipher_rsa = PKCS1_OAEP.new(pub_key)
	ciphertext = cipher_rsa.encrypt(plaintext)
	
	dictionary = {
		"head": "RSA Encryption",
		"ciphertext": b64encode(ciphertext).decode('utf-8')
	}
	
	#Return JSON readable format	
	return dictionary

def switch(option):
	if option == 'A': #AES Encryption scheme
	
		print("you chose AES encryption")
		#Generate AES keys
		key = generate_AESkey(16)
		iv = generate_AESiv(16)	
		#Run encryption function on data with manual input for block size, key, and iv
		#Rturns dictionary of data
		ciphertext = aes_encrypt(plaintext,key,iv, 16)
		
		return ciphertext	
		
	elif option == 'R': #RSA Encryption scheme
	
		print("you chose RSA encryption")
		
		ciphertext = rsa_encrypt(plaintext)
				
		return ciphertext
		
	else:
		#reinput encryption type
		print("incorrect input option")
		option = input("choose encryption type: ")
		switch(option.upper())

if __name__ == '__main__':
	
	script, option , uInput = argv
	
	while len(uInput) != 18:
		print("message must be 18 bytes input again")
		uInput = input("message: ")

	#Need to take user input from command line

	plaintext = uInput.encode('utf-8')
	
	#use option to run the determined encryption type
	encrypted_data = switch(option.upper())

	
	#Creates json object
	jObj = json.dumps(encrypted_data, indent=4)

	#Writes obj to json file
	with open("data.json", "w") as outfile:
		outfile.write(jObj)
	


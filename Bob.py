from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from base64 import b64encode
from base64 import b64decode
import json
import rsa

def aes_decrypt(ciphertext, aes_key, aes_iv, block_size):
	
	plain = AES.new(aes_key, AES.MODE_CBC, aes_iv)
	plaintext = unpad(plain.decrypt(ciphertext), block_size)
	
	return plaintext

def rsa_decrypt(ciphertext, priv_key):

	cipher_rsa = PKCS1_OAEP.new(priv_key)
	plaintext = cipher_rsa.decrypt(ciphertext)
	
	return plaintext
	
def recover(jObj):
	
	#run dependent decryption
	if jObj['head'] == "AES Encryption":
		print("using AES")
	
		ctext = jObj['ciphertext']
	
		key = jObj['aes_key']
		iv = jObj['aes_iv']
		
		b_size = 16
		
		plain = aes_decrypt(b64decode(ctext),b64decode(key),b64decode(iv), b_size)
		
	elif jObj['head'] == "RSA Encryption":
		print("using RSA")
	
		ctext = b64decode(jObj['ciphertext'])
	
		with open("rsa_key_data.json", 'r') as f:
			newObj = json.load(f)
			
		priv_key = RSA.import_key(b64decode(newObj['priv_key']))
		
		plain = rsa_decrypt(ctext, priv_key)
	
	return plain

if __name__ == "__main__":

	with open("data.json", 'r') as infile:
		jObj = json.load(infile)
		
	message = recover(jObj)
	

	print(message) 
	
else:
	
	#Generate key data for bob
	key = RSA.generate(2048)
	priv_key = key.export_key()
	pub_key = key.publickey().export_key()
	
	
	#Store key data in dictionary
	dictionary = {
		"head": "RSA Encryption Data",
		"priv_key": b64encode(priv_key).decode('utf-8'),
		"pub_key": b64encode(pub_key).decode('utf-8')
	}
	
	#dump dictionary into json object
	jObj = json.dumps(dictionary, indent=4)
		
	#write json object to data file for ALice to collect
	with open("rsa_key_data.json", 'w') as outFile:
		outFile.write(jObj)
		
		
		
		

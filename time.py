from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from sys import argv
import time
import json
from Alice import *

	
def key_pair(key_size):

	aes_key = generate_AESkey(key_size)
	aes_iv = generate_AESiv(16)
	
	data = [aes_key,aes_iv]
	
	return data

def aes_encrypt(plaintext, key, iv):
	
	cipher_aes = AES.new(key, AES.MODE_CBC, iv)
	ciphertext = cipher_aes.encrypt(pad(plaintext,16))
	
	return ciphertext

def aes_decrypt(ciphertext, key, iv):
	
	plain = AES.new(key, AES.MODE_CBC, iv)
	plaintext = unpad(plain.decrypt(ciphertext), 16)
	
	return plaintext

def run_aes(plaintext, key_size):

	eTmp = 0
	dTmp = 0
	data = key_pair(key_size)
	
	key = data[0]
	iv = data[1]
	
	for i in range(99):
		start_ae = time.time()
		ciphertext = aes_encrypt(plaintext, key, iv)
		end_ae = time.time()
		
		eTmp += (end_ae - start_ae)
		
	for i in range(99):
		start_ad = time.time()
		plaintext = aes_decrypt(ciphertext, key, iv)
		end_ad = time.time()
		
		dTmp += (end_ad - start_ad)

	avgEncrypt = eTmp / 100
	avgDecrypt = dTmp / 100
	
	return [avgEncrypt, avgDecrypt]
	
def rsa_encrypt(plaintext, pub_key):

	pub_key = RSA.import_key(pub_key)
	cipher_rsa = PKCS1_OAEP.new(pub_key)
	ciphertext = cipher_rsa.encrypt(plaintext)

	return ciphertext
	
def rsa_decrypt(ciphertext, priv_key):
	
	priv_key = RSA.import_key(priv_key)
	cipher_rsa = PKCS1_OAEP.new(priv_key)
	plaintext = cipher_rsa.decrypt(ciphertext)
	
	return plaintext
	
def full_rsa(plaintext, key_size):

	eTmp = 0
	dTmp = 0
		
	key = RSA.generate(key_size)
	priv_key = key.export_key()
	pub_key = key.publickey().export_key()
	
	for i in range(99):
		start_re = time.time()
		ciphertext = rsa_encrypt(plaintext, pub_key)
		end_re = time.time()
			
		eTmp += (end_re - start_re)
		
	for i in range(99):
		start_rd = time.time()
		plaintext = rsa_decrypt(ciphertext, priv_key)
		end_rd = time.time()
		
		dTmp += (end_rd - start_rd)
	
		
	avgEncrypt = eTmp / 100
	avgDecrypt = dTmp / 100
	
	return [avgEncrypt, avgDecrypt]
	
def run(plaintext):

	aes_128_data = run_aes(plaintext, 16)
	
	aes_192_data = run_aes(plaintext, 24)
	
	aes_256_data = run_aes(plaintext, 32)
	
	rsa_1024_data = full_rsa(plaintext, 1024)
	
	rsa_2048_data = full_rsa(plaintext, 2048)
	
	rsa_4096_data = full_rsa(plaintext, 4096)
	
	aes_e = {
	
		"128-bit": aes_128_data[0],
		"192-bit": aes_192_data[0],
		"256-bit": aes_256_data[0]
	
	}
	
	aes_d = {
	
		"128-bit": aes_128_data[1],
		"192-bit": aes_192_data[1],
		"256-bit": aes_256_data[1]
	
	}
	
	aes = {
	
		"encryption": aes_e,
		"decryption": aes_d
	
	}
	
	rsa_e = {
	
		"1024-bit": rsa_1024_data[0],
		"2048-bit": rsa_2048_data[0],
		"4096-bit": rsa_4096_data[0]
	
	}
	
	rsa_d = {
	
		"1024-bit": rsa_1024_data[1],
		"2048-bit": rsa_2048_data[1],
		"4096-bit": rsa_4096_data[1]
	
	}
	
	rsa = {
	
		"encryption": rsa_e,
		"decryption": rsa_d
	
	}

	dictionary = {
				
		"AES": aes,
		"RSA": rsa
		
	}
	
	return dictionary
	
	
def results(dictionary):

	jObj = json.dumps(dictionary, indent=4)
	
	with open("results.json", 'w') as out:
		out.write(jObj)
	
	return jObj
		
	
if __name__ == '__main__':

	script, userInput = argv
	
	while len(userInput) != 18:
		print("message must be 18 bytes input again")
		userInput = input("message: ")

	plaintext = userInput.encode('utf-8')

	obj = results(run(plaintext))
	
	print(obj)
	





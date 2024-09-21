{using:
	(pycryptodome
		{Crypto.Util - padding / unpadding}
		{Crypto.Cipher - AES, PKCS1_OAEP}
		{Crypto.PublicKey - RSA})
	{json}
	{b64 encode}
	{get_random_bytes}
	{sys argv}
}
{libraries:
	(pip install pycryptodome)
	(pip install rsa)
}
{running instructions:
	{program Alice.py takes command line input in order: 
		(encryption type: ('A' || 'a') for AES encryption || ('R' || 'r') for RSA encryption)
		(encrypted message: must be contained in ('...' || "...") format)
  	}
	(program Bob.py does not take in inputs but should be ran after Alice program)
 
}


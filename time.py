from Crypto.Util.Padding import pad
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from sys import argv
import json
import rsa
import Bob
import Alice

script, plaintext = argv

print(plaintext)

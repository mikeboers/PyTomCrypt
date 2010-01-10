
from base64 import b64encode

from _cipher import *

if __name__ == '__main__':
        
    aes = Cipher('0123456789abcdef')
    enc = aes.ecb_encrypt('0123456789abcdef')
    dec = aes.ecb_decrypt(enc)
    
    print dec, b64encode(enc)

from base64 import b64encode

from _crypto import *

if __name__ == '__main__':
        
    aes = Cipher('0123456789abcdef')
    enc = aes.encrypt('0123456789abcdef')
    dec = aes.decrypt(enc)
    
    print dec, b64encode(enc)
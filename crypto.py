
from base64 import b64encode

from _crypto import AES

if __name__ == '__main__':
        
    aes = AES('0123456789abcdef')
    enc = aes.encrypt('hellothere1234567890')
    dec = aes.decrypt(enc)
    
    print dec, b64encode(enc)
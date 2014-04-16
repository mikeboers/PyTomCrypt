import timeit

setup = """
import os
from tomcrypt.cipher import Cipher
key = os.urandom(32)
"""

init = """
encryptor = Cipher(key=key, cipher='aes', mode='gcm')
decryptor = Cipher(key=key, cipher='aes', mode='gcm')
"""

loop = """
iv = os.urandom(16)
plaintext = os.urandom(1024).encode('hex')

encryptor.reset()
encryptor.add_iv(iv)
encryptor.add_aad('ok')
ciphertext = encryptor.encrypt(plaintext)
encrypt_tag = encryptor.done()

decryptor.reset()
decryptor.add_iv(iv)
decryptor.add_aad('ok')
newtext = decryptor.decrypt(ciphertext)
decrypt_tag = decryptor.done()

if encrypt_tag != decrypt_tag: raise ValueError
if newtext != plaintext: raise ValueError
"""

ecb_init = """
encryptor = Cipher(key=key, cipher='aes', mode='ecb')
decryptor = Cipher(key=key, cipher='aes', mode='ecb')
"""

ecb_loop = """
plaintext = os.urandom(1024).encode('hex')
ciphertext = encryptor.encrypt(plaintext)
newtext = decryptor.decrypt(ciphertext)
if newtext != plaintext: raise ValueError

"""

n = 10000
print("GCM using tables:")
print(timeit.Timer(stmt=loop, setup=setup+init).repeat(3, n))

print("No GCM acceleration:")
print(timeit.Timer(stmt=init+loop, setup=setup).repeat(3, n))

print("ECB reference:")
print(timeit.Timer(stmt=ecb_loop, setup=setup+ecb_init).repeat(3, n))

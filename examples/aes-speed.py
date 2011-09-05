import time

from tomcrypt.cipher import Cipher


cipher = Cipher('0123456789abcdef', cipher='aes', mode='ecb')
start_time = time.time()
txt = '0123456789abcdef'
for i in xrange(50000):
    txt = cipher.encrypt(txt)
for i in xrange(50000):
    txt = cipher.decrypt(txt)
print 'Each AES block done in %.2fns' % ((time.time() - start_time) * 10**9 / 10**5)    
assert txt == '0123456789abcdef', 'speed test is wrong: %r' % txt
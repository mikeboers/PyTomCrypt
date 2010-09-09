from __future__ import division

import time
import os
import fractions

from tomcrypt.cipher import Cipher


chunk_len = 16
max_len = chunk_len * 2**14

print 'Testing on %d bytes of random content.' % max_len
print

while chunk_len <= max_len:
    
    chunks = [os.urandom(chunk_len) for i in xrange(max_len // chunk_len)]
    cipher = Cipher(cipher='aes', mode='ecb', key='0123456789abcdef')
    start_time = time.time()
    while chunks:
        out = cipher.encrypt(chunks.pop())
    duration = time.time() - start_time
    blocks = max_len // cipher.block_size
    print '%4s blocks: %.2fns each' % (fractions.Fraction(chunk_len, cipher.block_size), duration * 1000000000 / blocks)

    chunk_len *= 2




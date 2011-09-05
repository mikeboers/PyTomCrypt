from __future__ import division

import os
import time
from subprocess import Popen, PIPE
from unittest import TestCase, main

from tomcrypt import cipher
from tomcrypt.cipher import *

class CipherTests(TestCase):
    
    def test_library(self):
        cipher.test_library()    
    
    def test_against_openssl(self):
        for cipher_name in 'aes', 'des':
            cipher_desc = Descriptor(cipher=cipher_name)
            keysizes = []
            for i in range(cipher_desc.min_key_size, cipher_desc.max_key_size + 1):
                keysizes.append(cipher_desc.key_size(i))
            keysizes = list(sorted(set(keysizes)))
            for mode in 'ecb', 'cbc', 'cfb', 'ofb':
                for keysize in keysizes:
                    keysize *= 8
                    self.check_openssl(cipher_name, keysize, mode)

    def check_openssl(self, cipher_name, keysize, mode):
        cipher_desc = Descriptor(cipher=cipher_name)
        for i in xrange(1, 2):
            key = os.urandom(keysize//8)
            iv  = os.urandom(cipher_desc.block_size)
            pt  = os.urandom(i * 128 // 8)
            if cipher_name == 'aes':
                cipher_spec = 'aes-%d-%s' % (keysize, mode)
            elif cipher_name == 'des':
                cipher_spec = 'des-%s' % mode
            elif cipher_name == 'blowfish':
                cipher_spec = 'bf-%s' % mode
            proc = Popen(('openssl enc -e -%s -nopad -nosalt -K %s -iv %s' % (cipher_spec, key.encode('hex'), iv.encode('hex'))).split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
            out, err = proc.communicate(pt)
            self.assertFalse(err, err)
            cipher = Cipher(key=key, iv=iv, cipher=cipher_name, mode=mode)
            ct = cipher.encrypt(pt)
            self.assertEqual(ct, out, '%s %s %s: %s != %s' % (cipher_name, keysize, mode, ct.encode('hex'), out.encode('hex')))
            
    def test_vectors(self):
        for filename in os.listdir('test_vectors'):
            if 'CFB1' in filename:
                continue
            self.check_vectors(filename)

    def check_vectors(self, filename):
        mode = filename[:3].lower()
        fh = open('test_vectors/' + filename, 'rb')
        type = fh.readline().strip()[1:-1].lower()
        fh.readline()
        data = {}
        for line in fh:
            line = line.strip()
            if not line and data:
                key = data['key'].decode('hex')
                iv  = data.get('iv', '').decode('hex')
                pt  = data['plaintext'].decode('hex')
                ct  = data['ciphertext'].decode('hex')
                cipher = Cipher(key=key, iv=iv or None, cipher='aes', mode=mode)
                if type == 'encrypt':
                    res = cipher.encrypt(pt)
                    self.assertEqual(res, ct, '%s #%s: %s != %s' % (filename, data['count'], res.encode('hex'), data['ciphertext']))
                data = {}
            if ' = ' not in line:
                continue
            k, v = line.lower().split(' = ')
            data[k] = v

    def test_api(self):
        self.assertTrue('aes' in cipher.names, 'no AES')
        key = '0123456789abcdef'
        msg = 'hello, world'
        enc = cipher.aes(key).encrypt(msg)
        self.assertEqual(cipher.aes(key).decrypt(enc), msg)


if __name__ == '__main__':
    main()

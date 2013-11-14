from __future__ import division

from . import *

from tomcrypt import cipher
from tomcrypt.cipher import *


def load_tests(loader, tests, ignore):
    tests.addTests(get_doctests(cipher))
    return tests


class CipherAPITests(TestCase):

    def test_convience_args(self):

        # Args should be: key, iv, mode.
        nonzero = b'0123456789abcdef'
        z = cipher.aes(nonzero, nonzero, 'cbc')

    def test_iv_requirements(self):

        zero = b'\0' * 16
        nonzero = b'0123456789abcdef'
        
        # ECC
        x = cipher.aes(nonzero, mode='ecb')
        y = cipher.aes(nonzero, None, 'ecb')
        self.assertRaises(ValueError, cipher.aes, nonzero, zero, 'ecb')
        self.assertRaises(ValueError, cipher.aes, nonzero, nonzero, 'ecb')

        # Not ECC
        self.assertRaises(ValueError, cipher.aes, nonzero, mode='ctr')
        self.assertRaises(ValueError, cipher.aes, nonzero, None, 'ctr')
        x = cipher.aes(nonzero, zero, 'ctr')
        y = cipher.aes(nonzero, nonzero, 'ctr')

    def test_iv_getset(self):

        nonzero = b'0123456789abcdef'
        x = cipher.aes(nonzero, None, 'ecb')
        self.assertRaises(ValueError, x.get_iv)
        self.assertRaises(ValueError, x.set_iv, nonzero)


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
        for i in range(1, 2):
            key = os.urandom(keysize//8)
            iv = None if mode == 'ecb' else os.urandom(cipher_desc.block_size)
            pt = os.urandom(i * 128 // 8)
            if cipher_name == 'aes':
                cipher_spec = 'aes-%d-%s' % (keysize, mode)
            elif cipher_name == 'des':
                cipher_spec = 'des-%s' % mode
            elif cipher_name == 'blowfish':
                cipher_spec = 'bf-%s' % mode
            proc = Popen(('openssl enc -e -%s -nopad -nosalt -K %s -iv %s' %
                (cipher_spec, b16encode(key).decode(), b16encode(iv or b'\0').decode())).split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
            out, err = proc.communicate(pt)
            self.assertFalse(err, err)
            cipher = Cipher(key=key, iv=iv, cipher=cipher_name, mode=mode)
            ct = cipher.encrypt(pt)
            self.assertEqual(ct, out, '%s %s %s: %s != %s' % (cipher_name,
                keysize, mode, b16encode(ct).decode(), b16encode(out).decode()))
            
    def test_vectors(self):
        for filename in os.listdir('test_vectors'):
            if 'CFB1' in filename:
                continue
            self.check_vectors(filename)

    def check_vectors(self, filename):
        mode = filename[:3].lower()
        fh = open('test_vectors/' + filename, 'r')
        type = fh.readline().strip()[1:-1].lower()
        fh.readline()
        data = {}
        for line in fh:
            line = line.strip()
            if not line and data:
                key = b16decode(data['key'].encode(), True)
                iv  = b16decode(data.get('iv', '').encode(), True)
                pt  = b16decode(data['plaintext'].encode(), True)
                ct  = b16decode(data['ciphertext'].encode(), True)
                cipher = Cipher(key=key, iv=iv or None, cipher='aes', mode=mode)
                if type == 'encrypt':
                    res = cipher.encrypt(pt)
                    self.assertEqual(res, ct, '%s #%s: %s != %s' % (filename,
                        data['count'], b16encode(res), data['ciphertext']))
                data = {}
            if ' = ' not in line:
                continue
            k, v = line.lower().split(' = ')
            data[k] = v
        fh.close()

    def test_api(self):
        self.assertTrue('aes' in cipher.names, 'no AES')
        key = b'0123456789abcdef'
        iv  = b'0' * 16
        msg = b'hello, world'
        enc = cipher.aes(key, iv).encrypt(msg)
        self.assertEqual(cipher.aes(key, iv).decrypt(enc), msg)

    def test_bytearrays(self):
        key = b'0123456789abcdef'
        iv  = b'0' * 16
        msg = bytearray(b'hello, world')
        enc = cipher.aes(key, iv).encrypt(msg)
        self.assertEqual(cipher.aes(key, iv).decrypt(enc), msg)


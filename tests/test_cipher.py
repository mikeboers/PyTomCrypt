from __future__ import division

import os
import time
from subprocess import Popen, PIPE

from tomcrypt import cipher
from tomcrypt.cipher import *

def test_library():
    cipher.test_library()
    
def test_speed():
    cipher = Cipher('0123456789abcdef', cipher='aes', mode='ecb')
    start_time = time.time()
    txt = '0123456789abcdef'
    for i in xrange(50000):
        txt = cipher.encrypt(txt)
    for i in xrange(50000):
        txt = cipher.decrypt(txt)
    print 'Each AES block done in %.2fns' % ((time.time() - start_time) * 10**9 / 10**5)    
    assert txt == '0123456789abcdef', 'speed test is wrong: %r' % txt
    
    
def test_against_openssl():
    for cipher_name in 'aes', 'des':
        cipher_desc = Descriptor(cipher=cipher_name)
        keysizes = []
        for i in range(cipher_desc.min_key_size, cipher_desc.max_key_size + 1):
            keysizes.append(cipher_desc.key_size(i))
        keysizes = list(sorted(set(keysizes)))
        for mode in 'ecb', 'cbc', 'cfb', 'ofb':
            for keysize in keysizes:
                keysize *= 8
                yield check_openssl, cipher_name, keysize, mode

def check_openssl(cipher_name, keysize, mode):
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
        assert not err, err
        cipher = Cipher(key=key, iv=iv, cipher=cipher_name, mode=mode)
        ct = cipher.encrypt(pt)
        assert ct == out, '%s %s %s: %s != %s' % (cipher_name, keysize, mode, ct.encode('hex'), out.encode('hex'))
            
def test_vectors():
    for filename in os.listdir('test_vectors'):
        if 'CFB1' in filename:
            continue
        check_vectors(filename)

def check_vectors(filename):
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
                assert res == ct, '%s #%s: %s != %s' % (name, data['count'], res.encode('hex'), data['ciphertext'])
            data = {}
        if ' = ' not in line:
            continue
        k, v = line.lower().split(' = ')
        data[k] = v

def test_api():
    assert 'aes' in cipher.names
    key = '0123456789abcdef'
    msg = 'hello, world'
    enc = cipher.aes(key).encrypt(msg)
    assert cipher.aes(key).decrypt(enc) == msg



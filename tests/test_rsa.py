from __future__ import division, print_function

from . import *

from tomcrypt import prng, rsa, utils, LibError
from tomcrypt.hash import md5, sha1
from tomcrypt.rsa import *


def load_tests(loader, tests, ignore):
    tests.addTests(get_doctests(rsa))
    return tests


class TestRSABasics(TestCase):
    
    def setUp(self):
        self.private = self.key = Key(1024)
        self.public = self.key.public

    def test_key_size_for_payload(self):
        payload = 100
        size = key_size_for_payload(payload)
        key = Key(size)
        self.assertEqual(size, key.size)
        self.assertEqual(payload, key.max_payload())
        
    def test_as_string(self):
        key = Key(1024)
        self.assertTrue('BEGIN RSA PRIVATE' in key.as_string())
        self.assertTrue('BEGIN PUBLIC' in key.as_string('public'))
        self.assertTrue('BEGIN PUBLIC' in key.public.as_string())

    def test_no_padding(self):
        key = Key(1024)
        ct1 = key.encrypt(b"hello", padding="none")
        ct2 = key.encrypt(b"hello", padding="none")
        pt = key.decrypt(ct1, padding="none").lstrip(b'\0')
        self.assertEqual(ct1, ct2)
        self.assertEqual(pt, b"hello")

    def test_encrypt(self):
        key = Key(1024)
        pt1 = b"hello world"
        ct1 = key.encrypt(pt1)
        ct2 = key.encrypt(pt1)
        pt2 = key.decrypt(ct1)

        self.assertEqual(pt1, pt2)
        self.assertNotEqual(ct1, ct2)

    def test_sign(self):
        key = Key(1024)
        msg = b"hello world"
        sig = key.sign(msg)
        self.assertTrue(key.verify(msg, sig))
        # Not testing failure.

    def test_raw_passthrough_forwards(self):
        msg = b'hello world'
        ct = self.public.encrypt(msg, padding='none')
        pt = self.private.decrypt(ct, padding='none').strip(b'\0')
        self.assertEqual(msg, pt)

    def test_raw_passthrough_backwards(self):
        msg = b'hello world'
        ct = self.private.decrypt(msg, padding='none')
        pt = self.public.encrypt(ct, padding='none').strip(b'\0')
        self.assertEqual(msg, pt)

    def test_malformed_key(self):
        key_pem = '-----BEGIN RSA PRIVATE KEY-----\n%s-----END RSA PRIVATE KEY-----' % 'malformed'.encode('base64')
        self.assertRaises(LibError, Key, key_pem)


class TestRsaWithOpenssl(TestCase):

    def setUp(self):

        self.key = Key(1024)
        self.private_path = os.path.join(self.sandbox, 'private.pem')
        self.public_path = os.path.join(self.sandbox, 'public.pem')

        with open(self.private_path, 'w') as key_fh:
            key_fh.write(self.key.as_string())
        with open(self.public_path, 'w') as key_fh:
            key_fh.write(self.key.public.as_string())

    def test_tomcrypt_decrypt_openssl_oaep(self):

        message = b'This is a test message.'
        proc = Popen(
            ['openssl', 'rsautl', '-encrypt', '-oaep', '-pubin', '-inkey', self.public_path],
            stdin=PIPE,
            stdout=PIPE,
        )
        ct, err = proc.communicate(message)

        pt = self.key.decrypt(ct)
        self.assertEqual(message, pt)

    def test_tomcrypt_decrypt_openssl_pkcs(self):

        message = b'This is a test message.'
        proc = Popen(
            ['openssl', 'rsautl', '-encrypt', '-pkcs', '-pubin', '-inkey', self.public_path],
            stdin=PIPE,
            stdout=PIPE,
        )
        ct, err = proc.communicate(message)

        pt = self.key.decrypt(ct, padding='v1.5')
        self.assertEqual(message, pt)

    def test_tomcrypt_verify_openssl(self):

        message = b'This is a test message.'
        hash_ = sha1(message).digest()
        proc = Popen(
            ['openssl', 'rsautl', '-sign', '-inkey', self.private_path],
            stdin=PIPE,
            stdout=PIPE,
        )
        sig, err = proc.communicate(hash_)

        pt = self.key.verify(sig, padding='none')
        pt = pt[pt.index(b'\0', 1) + 1:]
        self.assertEqual(hash_, pt)

  



class TestRsaWithM2Crypto(TestCase):

    def setUp(self):

        self.message = 'Hello, M2Crypto!'

        self.key = Key(1024)
        self.private_path = os.path.join(self.sandbox, 'private.pem')
        self.public_path = os.path.join(self.sandbox, 'public.pem')

        with open(self.private_path, 'w') as key_fh:
            key_fh.write(self.key.as_string())
        with open(self.public_path, 'w') as key_fh:
            key_fh.write(self.key.public.as_string())

    def test_M2Crypto_sign_and_tomcrypt_verify(self):


        import M2Crypto
        key = M2Crypto.RSA.load_key_string(self.key.as_string())
        sig = key.sign(self.message, 'sha256')

        # From this we can see that M2Crypto is *NOT* hashing the input!
        recovered = self.key.encrypt(sig, padding='none')
        self.assertEqual(self.message, recovered[-len(self.message):])

        # This should **NOT** be passing if libtomcrypt hashes the messages for us.
        self.assertTrue(self.key.verify(self.message, sig, padding='v1.5', hash='sha256'))





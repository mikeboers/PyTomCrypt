
from tomcrypt import hash as hash_, rsa

key = rsa.Key(1024)
message = 'Hello, RSA!'


def use_pycrypto(plaintext, private_pem):
    key = self.Crypto.PublicKey.RSA.importKey(private_pem)
    digest = self.Crypto.Hash.SHA256.new(plaintext)
    return self.Crypto.Signature.PKCS1_v1_5.new(key).sign(digest)

def use_openssl(plaintext, private_pem):
    path = self.mkstemp(private_pem)
    # http://stackoverflow.com/questions/11221898/
    signature = self.openssl('sha256', '-sign', path, stdin=plaintext)
    imp.os.unlink(path)
    return signature

def use_m2crypto(plaintext, private_pem):
    key = self.M2Crypto.RSA.load_key_string(private_pem)
    signature = key.sign(self.sha256(plaintext), 'sha256')
    return signature

def use_pytomcrypt(plaintext, private_pem):
    key = self.tomcrypt.rsa.Key(private_pem)
    return key.sign(self.sha256(plaintext), hash='sha256', padding='v1.5')


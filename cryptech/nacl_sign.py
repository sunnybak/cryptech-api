import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import Base64Encoder, HexEncoder
import nacl.signing, nacl.encoding, nacl.hash
import base64
import hashlib
import time

def create_cipher(private_key, public_key):
    return Box(private_key, public_key)


def encrypt(msg, cipher):
    return cipher.encrypt(bytes(msg, 'utf-8'), encoder=nacl.encoding.HexEncoder).decode('utf-8')


def decrypt(msg, cipher):
    return cipher.decrypt(bytes(msg, 'utf-8'), encoder=nacl.encoding.HexEncoder).decode('utf-8')


def generate_keys():
    rk = PrivateKey.generate()
    uk = rk.public_key
    return nacl.encoding.HexEncoder.encode(bytes(rk)).decode('utf-8'), nacl.encoding.HexEncoder.encode(bytes(uk)).decode('utf-8')


def hash_msg(msg):
    return nacl.hash.sha256(bytes(msg, 'utf-8'), encoder=nacl.encoding.HexEncoder).decode('utf-8')


def sign(msg, auth_rk, PUB_uk):
    auth_rk = PrivateKey(private_key=bytes(auth_rk, 'utf-8'), encoder=nacl.encoding.HexEncoder)
    return encrypt(msg, create_cipher(auth_rk, PUB_uk))


def verify(msg, sign, auth_pk):
    # try: return decrypt(sign.sign, create_cipher(s.rk, auth_pk)) == msg
    # except: return False
    auth_pk = PublicKey(public_key=bytes(auth_pk, 'utf-8'),encoder=nacl.encoding.HexEncoder)
    return decrypt(sign.sign, create_cipher(sign.rk, auth_pk)) == msg


class Sign(object):

    def __init__(self, msg=None, auth_rk=None, sign=None):
        self.rk = PrivateKey(
            private_key=bytes('d90cacd31e22c63ce99f062e88d6d2734e944e8d3dac895a67472701b6c55c7e', 'utf-8'),
            encoder=nacl.encoding.HexEncoder)
        self.uk = PublicKey(
            public_key=bytes('1a41da8aa64dc15e26e8ca787d35d559c10774d4a8e8c373418a0b0862f6567c', 'utf-8'),
            encoder=nacl.encoding.HexEncoder)
        if not sign:
            auth_rk = PrivateKey(private_key=bytes(auth_rk, 'utf-8'), encoder=nacl.encoding.HexEncoder)
            self.sign = encrypt(msg, create_cipher(auth_rk, self.uk))
        else:
            self.sign = sign

    def __str__(self): return self.sign




if __name__ == "__main__":
    rk_A = '4c793701b52477ffa792a3195e39d666c847dbe1763b453a3a5b60a6bb547238'
    uk_A = '9db8ecffe9b9f9cb3778f613189636b3c74be20b3353df0b8dded184729e382b'
    msg = 'Shikhar Bakhda'

    t = str(int(time.time()))
    m = hash_msg(msg)
    s = Sign(m, rk_A)
    v = verify(m, Sign(sign='1ae4f0e89e35677cae35b584ad14b6aadae16d012b05d4263733d14d4f58e53e380899350f67c88d33dd156bf5be5891951b07f9a95ef7c62d94b02668b95337979058d8425c94572cc5fb72e33f636649d8eac5fc38260b3a94abb7a76d5b0408d59cc9fbea5652'), uk_A)

    print('Time: ' + t)
    print('Msg : ' + m)
    print('Sign: ' + str(s))
    print('Verf: ' + str(v))
    # print('Pruf: ' + p)
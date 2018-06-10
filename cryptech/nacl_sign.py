import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import Base64Encoder, HexEncoder
import nacl.signing, nacl.encoding, nacl.hash
import time

def nonce(nonce):
    return bytes(nonce[0:24].ljust(24, '\0'), 'utf-8')

def create_cipher(private_key, public_key):
    return Box(private_key, public_key)


def encrypt(msg, cipher, nonce=None):
    return cipher.encrypt(bytes(msg, 'utf-8'), encoder=nacl.encoding.HexEncoder, nonce=nonce).decode('utf-8')


def decrypt(msg, cipher):
    return cipher.decrypt(bytes(msg, 'utf-8'), encoder=nacl.encoding.HexEncoder).decode('utf-8')


def generate_keys():
    rk = PrivateKey.generate()
    uk = rk.public_key
    return nacl.encoding.HexEncoder.encode(bytes(rk)).decode('utf-8'), nacl.encoding.HexEncoder.encode(bytes(uk)).decode('utf-8')


def hash_msg(msg):
    return nacl.hash.sha256(bytes(msg, 'utf-8'), encoder=nacl.encoding.HexEncoder).decode('utf-8')


def sign(msg, auth_rk, PUB_uk, nonce=None):
    auth_rk = PrivateKey(private_key=bytes(auth_rk, 'utf-8'), encoder=nacl.encoding.HexEncoder)
    return encrypt(msg, create_cipher(auth_rk, PUB_uk), nonce=nonce)


def verify(msg, sign, auth_pk):
    try:
        auth_pk = PublicKey(public_key=bytes(auth_pk, 'utf-8'), encoder=nacl.encoding.HexEncoder)
        return decrypt(sign.sign, create_cipher(sign.rk, auth_pk)) == msg
    except:
        return False


class Sign(object):

    def __init__(self, msg=None, auth_rk=None, nonce=None, sign=None):
        # self.rk = PrivateKey.generate()
        # self.uk = self.rk.public_key
        self.rk = PrivateKey(
            private_key=bytes('d90cacd31e22c63ce99f062e88d6d2734e944e8d3dac895a67472701b6c55c7e', 'utf-8'),
            encoder=nacl.encoding.HexEncoder)
        self.uk = PublicKey(
            public_key=bytes('1a41da8aa64dc15e26e8ca787d35d559c10774d4a8e8c373418a0b0862f6567c', 'utf-8'),
            encoder=nacl.encoding.HexEncoder)

        if not sign:
            auth_rk = PrivateKey(private_key=bytes(auth_rk, 'utf-8'), encoder=nacl.encoding.HexEncoder)
            self.sign = encrypt(msg, create_cipher(auth_rk, self.uk), nonce=nonce)
        else:
            self.sign = sign

    def __str__(self): return self.sign




if __name__ == "__main__":
    # rk_A = '4c793701b52477ffa792a3195e39d666c847dbe1763b453a3a5b60a6bb547238'
    # uk_A = '9db8ecffe9b9f9cb3778f613189636b3c74be20b3353df0b8dded184729e382b'
    # msg = 'Shikhar Bakhda'
    #
    # n = nonce(hash_msg('shikharbakhda@gmail.commindstorms2.0'))
    # t = str(int(time.time()))
    # m = hash_msg(msg)
    # s = Sign(m, rk_A, n)
    # v = verify(m, s, uk_A)
    #
    # print('Time: ' + t)
    # print('Msg : ' + m)
    # print('Sign: ' + str(s))
    # print('Nonc: ' + str(s)[0:48])
    # print('Verf: ' + str(v))
    #
    # n = nonce(hash_msg('shikharbakhda@gmail.commindstorms2.0'))
    #
    # m = hash_msg(msg+'!')
    # s = Sign(m, rk_A, n)
    # v = verify(m, s, uk_A)
    #
    #
    # print('Time: ' + t)
    # print('Msg : ' + m)
    # print('Sign: ' + str(s))
    # print('Nonc: ' + str(s)[0:48])
    # print('Verf: ' + str(v))
    # # print('Pruf: ' + p)

    signature = '3166633237646136633461666664643435346163356366376f3242103bec9e9514efac269b0c96431c8ba88d13ee4d2f32f2a7bdb96bc4ca172955369cd1ff64bb8da85321c7c8b12aeea5129ea547dc5f6f107d9181dde0afeec865f4bfed960c42ab1b8f013080'
    content_hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    public_key = '37f7384d393b49d85e37263e411c2333e2464347f2670ff68d86bcdd00354606'
    print(str(verify(content_hash, Sign(sign=signature), public_key)))
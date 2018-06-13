import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import Base64Encoder
import nacl.signing, nacl.hash
import os, hashlib

def create_nonce(nonce=None, seed=None):
    if seed is not None:
        hashed_seed = hash_msg(seed)
        if seed == '': create_nonce(seed='0'*100)
        return str(bytes(hashed_seed, 'utf-8')[0:24].ljust(24, b'\0'),'utf-8')
    if nonce is not None:
        if type(nonce).__name__ == 'bytes':
            nonce = nonce[0:24].ljust(24, b'\0')
        if type(nonce).__name__ == 'str':
            nonce = bytes(nonce[0:24].ljust(24, '\0'), 'utf-8')
    return nonce


def create_cipher(private_key, public_key):
    return Box(private_key, public_key)


def encrypt(msg, cipher, nonce=None):
    return cipher.encrypt(bytes(msg, 'utf-8'), encoder=nacl.encoding.HexEncoder, nonce=create_nonce(nonce)).decode('utf-8')


def decrypt(msg, cipher):
    return cipher.decrypt(bytes(msg, 'utf-8'), encoder=nacl.encoding.HexEncoder).decode('utf-8')


def generate_keys():
    rk = PrivateKey.generate()
    uk = rk.public_key
    return {'private_key': nacl.encoding.HexEncoder.encode(bytes(rk)).decode('utf-8'),
            'public_key' : nacl.encoding.HexEncoder.encode(bytes(uk)).decode('utf-8')}


def hash_msg(msg):
    return nacl.hash.sha256(bytes(msg, 'utf-8'), encoder=nacl.encoding.HexEncoder).decode('utf-8')


def file_hash(file_name):
    BLOCKSIZE = 65536
    hasher = hashlib.sha1()
    with open(file_name, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(BLOCKSIZE)
    return hasher.hexdigest()


def sign(msg, auth_rk, PUB_uk, nonce=None):
    auth_rk = PrivateKey(private_key=bytes(auth_rk, 'utf-8'), encoder=nacl.encoding.HexEncoder)
    return encrypt(msg, create_cipher(auth_rk, PUB_uk), nonce=create_nonce(nonce))


def verify(msg, sign, auth_pk):
    try:
        auth_pk = PublicKey(public_key=bytes(auth_pk, 'utf-8'), encoder=nacl.encoding.HexEncoder)
        return decrypt(sign.sign, create_cipher(sign.rk, auth_pk)) == msg
    except:
        return False


def verify_nonce(nonce, sign):
    sign = sign[0:48]
    nonce_sign = Sign(msg='0', auth_rk='0' * 64, nonce=create_nonce(nonce=nonce)).sign[0:48]
    print(sign)
    print(nonce_sign)
    return sign == nonce_sign


class Sign(object):

    def __init__(self, msg=None, auth_rk=None, nonce=None, sign=None):
        self.create_properties()
        if sign:
            self.sign = sign
        else:
            auth_rk = PrivateKey(private_key=bytes(auth_rk, 'utf-8'), encoder=nacl.encoding.HexEncoder)
            self.sign = encrypt(msg, create_cipher(auth_rk, self.uk), nonce=nonce)

    def __str__(self):
        return self.sign


    @classmethod
    def create_properties(self):
        try:
            rk = os.environ.get('KNOWN_RK') or \
                 "d90cacd31e22c63ce99f062e88d6d2734e944e8d3dac895a67472701b6c55c7e"
            uk = os.environ.get('KNOWN_UK') or \
                "1a41da8aa64dc15e26e8ca787d35d559c10774d4a8e8c373418a0b0862f6567c"
        except:
            rk = 'd90cacd31e22c63ce99f062e88d6d2734e944e8d3dac895a67472701b6c55c7e'
            uk = '1a41da8aa64dc15e26e8ca787d35d559c10774d4a8e8c373418a0b0862f6567c'
        self.rk = PrivateKey(
            private_key=bytes(rk, 'utf-8'),
            encoder=nacl.encoding.HexEncoder)
        self.uk = PublicKey(
            public_key=bytes(uk, 'utf-8'),
            encoder=nacl.encoding.HexEncoder)

if __name__ == "__main__":
    rk_A = '4c793701b52477ffa792a3195e39d666c847dbe1763b453a3a5b60a6bb547238'
    uk_A = '9db8ecffe9b9f9cb3778f613189636b3c74be20b3353df0b8dded184729e382b'
    msg = 'Shikhar Bakhda'

    # n = create_nonce(seed='shikharbakhda@gmail.comsecretpass')
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
    # n = create_nonce(seed='shikharbakhda@gmail.comsecretpass')
    #
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

    import base64

    # rk = PrivateKey.generate()
    # x = nacl.encoding.Base64Encoder.encode(rk)
    # print(nacl.encoding.Base64Encoder.decode(x))
    #
    # print(nacl.encoding.HexEncoder.encode(bytes(rk)).decode('utf-8'))
    # print(base64.b64encode(bytes(rk, 'utf-8')).decode('utf8'))
    # print(base64.b64encode(rk).decode('utf8'))
# '38323534633332396139323835306636643533396464333712d4e3ca52b5c60ef18ab1dae3ff2e0c09d1df1ee1ba460cdfb215b858b70737fd13393019c0729d655a1d27c17ab265b881aaade8c7c95bc3c4b420490c6027d1e072c5980b0843bf70a9b8a5351095'
    import requests, json
    # key = '7250c6a4b2c45454e63558ce82f214aa0ffb64f8'
    #
    # guid = 'Bi6c31plwrT'
    # url="http://google.com"
    # payload = json.dumps({
    #     "long_url": url,
    #     "group_guid": guid
    # })
    # HEADERS = {'Content-Type': 'application/json', 'Authorization': key, 'Host': 'api-ssl.Bitly.com'}
    # res = requests.request(method='POST', url='https://api-ssl.Bitly.com/v4/shorten', data=payload, headers=HEADERS)
    # print(res.content)
    # print(json.loads(res.content)['link'])
    # import socket
    #
    # print(socket.gethostname())

    # url = "http://api.qrserver.com/v1/read-qr-code/"

    # payload = {"Content-Disposition": "form-data", "name":"file", "filename":"webcam.jpg","Content-Type": "image/jpeg"}
    # headers = {
    #     'Content-Type': "multipart/form-data"
    # }
    # "Content-Type": "image/jpeg"
    # payload = {"file": "webcam.jpg"}

    # url = "http://api.qrserver.com/v1/read-qr-code/"
    #
    # payload = "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"file\"; filename=\"webcam.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"MAX_FILE_SIZE\"\r\n\r\n1048576\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--"
    # headers = {
    #     'content-type': "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
    #     'Cache-Control': "no-cache",
    #     'Postman-Token': "c687e713-15e6-4398-a9b5-65cb1eb71e52"
    # }
    #
    # response = requests.request("POST", 'http://127.0.0.1:8000/test/', data=payload, headers=headers)
    #
    # print(response.text)

    # from qrtools.qrtools import QR
    # import zbar


    # my_QR = QR(filename="/Users/sbakhda/dev/cryptech/cryptech/static/webcam.jpg")

    # decodes the QR code and returns True if successful
    # my_QR.decode()

    # prints the data
    # print(my_QR.data)

    # from PIL import Image
    # import zbarlight
    #
    # file_path = 'webcam.jpg'
    # with open(file_path, 'rb') as image_file:
    #     image = Image.open(image_file)
    #     image.load()
    #
    # codes = zbarlight.scan_codes(['qrcode'], image)
    # print('QR codes: %s' % codes)
    #
    uk = '8a6953509ab98d41302c483035acbb380388b770a1cf578665b88490d271d842'
    rk = '9d53077ce5d42cda2383a816c5d774a5464e4372cfe725469624cfaee6270ca0'
    # rk2 = '9d5307ece5a42caa238aa816c5d774a5464e4372cfe725469624cfaee6270ca1'
    #
    def sp(s):
        print(s.sign[:48] + '\t' + s.sign[48:])
    #
    # def check_nonce(nonce_seed, sign):
    #     sign = sign[0:48]
    #     nonce_sign = Sign(msg='0', auth_rk='0'*64, nonce=create_nonce(seed=nonce_seed)).sign[0:48]
    #     return nonce_sign == sign
    #
    s = Sign(msg='shikhar',auth_rk=rk, nonce=create_nonce(seed='nonce'))
    s2 = Sign(msg='shikhar',auth_rk=rk, nonce=create_nonce(seed='nonce1'))
    # s3 = Sign(msg='shikhar',auth_rk=rk, nonce=create_nonce(seed='nonce1'))
    # s4 = Sign(msg='shikhar',auth_rk=rk, nonce=create_nonce(seed='nonce1'))
    #
    # print(check_nonce('nonce', s.sign))
    #
    sig = '306137383030393539313732326363383438323563613935534acae523fb3209ee78beea05c6c99c0c28baa4f8bf95'
    print(verify('shikhar',Sign(sign=sig), uk))
    print(verify('shikhar',Sign(sign=s.sign), uk))
    # sp(s)
    # sp(s2)
    # sp(s3)
    # sp(s4)
    # print(create_nonce(nonce='2bb80d537b1da3e38bd30361'))
    sp(s)
    sp(s2)
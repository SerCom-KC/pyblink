from hashlib import md5

from Crypto.Cipher import AES


class IMEncrypt:
    iv = b"\xf0\xe1\xd2\xc3\xb4\xa5\x96\x87\x78\x69\x5a\x4b\x3c\x2d\x5e\xaf"
    block_size = 16
    # padding algorithm is pkcs7

    def encode(skey, payload):
        key = md5(skey.encode("utf-8")).digest()
        cipher = AES.new(key, AES.MODE_CBC, IMEncrypt.iv)
        padding = b""
        if len(payload) % IMEncrypt.block_size:
            padding_len = IMEncrypt.block_size - \
                len(payload) % IMEncrypt.block_size
            padding = chr(padding_len)*padding_len
            padding = padding.encode("utf-8")
        return cipher.encrypt(payload+padding)

    def decode(skey, payload):
        key = md5(skey.encode("utf-8")).digest()
        cipher = AES.new(key, AES.MODE_CBC, IMEncrypt.iv)
        result = cipher.decrypt(payload)
        padding_len = result[-1]
        return result[:-padding_len] if result[-padding_len:] == (chr(padding_len)*padding_len).encode("utf-8") else result

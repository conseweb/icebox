
#!/usr/bin/env python3

import os
import argparse
from binascii import hexlify, unhexlify
import sys

from urllib.error import HTTPError

from pycoin.key import Key
from pycoin.tx.tx_utils import create_tx, sign_tx
from pycoin.services import spendables_for_address, get_tx_db
from pycoin.services.blockchain_info import send_tx

parser = argparse.ArgumentParser()
parser.add_argument(
    '--privkey-bytes', help='provide hexlified raw privkey bytes', default='', type=str)
parser.add_argument('--send-all-to', help='where to send all the money at this address',
                    default='1MaxKayeQg4YhFkzFz4x6NDeeNv1bwKKVA', type=str)
args = parser.parse_args()

key_bytes = unhexlify(args.privkey_bytes.encode()
                      ) if args.privkey_bytes != '' else os.urandom(32)
private_key = Key(secret_exponent=int.from_bytes(key_bytes, 'big'))
address = private_key.address()

print('Your Bitcoin address is...', address)
print('Your --privkey-bytes', hexlify(key_bytes).decode())

try:
    spendables = spendables_for_address(address, None)
    print('Spending', spendables)
except HTTPError as e:
    print('Blockchain throws a 500 error if there are no spendables. Try sending some coins to',
          address, 'and try again. Remeber to copy privkey-bytes.')
    sys.exit()

tx = create_tx(spendables, [args.send_all_to])
print('TX created:', repr(tx))

sign_tx(tx, [private_key.wif(False), private_key.wif(True)])
print('Final TX:', tx)

# print('TX Send Attempt:', send_tx(tx))



'''
tx_in = TxIn("<utxo hash in binary here>", <utxo position, usually between 0 and 5>)
script = standard_tx_out_script(address)
tx_out = TxOut(<btc amount to send - fee>, script)
tx = Tx(1, [tx_in], [tx_out])
lookup = <this part you have to figure out>
tx.sign(lookup)
print tx.as_hex()



def privateKeyToWif(key_hex):
    return utils.base58CheckEncode(0x80, key_hex.decode('hex'))


def privateKeyToPublicKey(s):
    sk = ecdsa.SigningKey.from_string(s.decode('hex'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return ('\04' + sk.verifying_key.to_string()).encode('hex')


def pubKeyToAddr(s):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(s.decode('hex')).digest())
    return utils.base58CheckEncode(0, ripemd160.digest())


def keyToAddr(s):
    return pubKeyToAddr(privateKeyToPublicKey(s))


# Makes a transaction from the inputs
# outputs is a list of [redemptionSatoshis, outputScript]
def makeRawTransaction(outputTransactionHash, sourceIndex, scriptSig, outputs):
    def makeOutput(data):
        redemptionSatoshis, outputScript = data
        return (struct.pack("<Q", redemptionSatoshis).encode('hex') +
                '%02x' % len(outputScript.decode('hex')) + outputScript)
    formattedOutputs = ''.join(map(makeOutput, outputs))
    return (
        "01000000" +  # 4 bytes version
        "01" +  # varint for number of inputs
        # reverse outputTransactionHash
        outputTransactionHash.decode('hex')[::-1].encode('hex') +
        struct.pack('<L', sourceIndex).encode('hex') +
        '%02x' % len(scriptSig.decode('hex')) + scriptSig +
        "ffffffff" +  # sequence
        "%02x" % len(outputs) +  # number of outputs
        formattedOutputs +
        "00000000"  # lockTime
    )


def makeSignedTransaction(privateKey, outputTransactionHash, sourceIndex, scriptPubKey, outputs):
    myTxn_forSig = (makeRawTransaction(outputTransactionHash, sourceIndex, scriptPubKey, outputs)
                    + "01000000")  # hash code

    s256 = hashlib.sha256(hashlib.sha256(
        myTxn_forSig.decode('hex')).digest()).digest()
    sk = ecdsa.SigningKey.from_string(
        privateKey.decode('hex'), curve=ecdsa.SECP256k1)
    sig = sk.sign_digest(
        s256, sigencode=ecdsa.util.sigencode_der) + '\01'  # 01 is hashtype
    pubKey = keyUtils.privateKeyToPublicKey(privateKey)
    scriptSig = utils.varstr(sig).encode(
        'hex') + utils.varstr(pubKey.decode('hex')).encode('hex')
    signed_txn = makeRawTransaction(
        outputTransactionHash, sourceIndex, scriptSig, outputs)
    verifyTxnSignature(signed_txn)
    return signed_txn


# Warning: this random function is not cryptographically strong and is just for example
private_key = ''.join(['%x' % random.randrange(16) for x in range(0, 64)])
print keyUtils.privateKeyToWif(private_key)
print keyUtils.keyToAddr(private_key)

source = 'mx8hhz3tWjbKkeeTXUyCPUuaJmY9U6SZse'
target = 'msT8A86DgsgTNkcyiYwb22DDUBopBJGAKb'
tx_in = TxIn("3ef58f2581ed01ab1ba231aeb77846d3340367e651fa6bb1022cdc2790e0698f", 0)
script = standard_tx_out_script(address)
# 0.15 btc
tx_out = TxOut(15000000, script)
tx = Tx(1, [tx_in], [tx_out])
lookup = <this part you have to figure out>
tx.sign(lookup)
print tx.as_hex()
'''

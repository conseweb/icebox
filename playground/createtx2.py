import struct
import base58
import hashlib
import ecdsa

import struct
import base58
import hashlib
import ecdsa
import bitcoin


Bob_addr = "mwRhL3S4NATBKDJkgbaa1PXGFUB9Qi1uuj"
bob_hashed_pubkey = base58.b58decode_check(Bob_addr)[1:].encode("hex")
print(bob_hashed_pubkey)
# print(base58.b58decode_check(Bob_addr)[1:])

Bob_private_key = "cQFXsyWHnz1CcxgDb1E4q7zLoB6jVzhCCGMyXSJaj74YGUik2N45"
prv_txid = "8310e8a8c65774651a658af96751cabbb89abd7c38661a95e662c923fa057238"


Charlie_adr = "mwRhL3S4NATBKDJkgbaa1PXGFUB9Qi1uuj"
charlie_hashed_pubkey = base58.b58decode_check(Charlie_adr)[1:].encode("hex")

class raw_tx:
    version         = struct.pack("<L", 1)
    tx_in_count     = struct.pack("<B", 1)
    tx_in           = {} #TEMP
    tx_out_count    = struct.pack("<B", 2)
    tx_out1         = {} #TEMP
    tx_out2         = {} #TEMP
    lock_time       = struct.pack("<L", 0)

def flip_byte_order(string):
    flipped = "".join(reversed([string[i:i+2] for i in range(0, len(string), 2)]))
    return flipped


rtx = raw_tx()

rtx.tx_in["txouthash"]      = flip_byte_order(prv_txid).decode("hex")
rtx.tx_in["tx_out_index"]   = struct.pack("<L", 1)
rtx.tx_in["script"]         = ("76a914%s88ac" % charlie_hashed_pubkey).decode("hex")
rtx.tx_in["scrip_bytes"]    = struct.pack("<B", len(rtx.tx_in["script"]))
rtx.tx_in["sequence"]       = "ffffffff".decode("hex")

rtx.tx_out1["value"]        = struct.pack("<Q", 100000)
rtx.tx_out1["pk_script"]    = ("76a914%s88ac" % bob_hashed_pubkey).decode("hex")
rtx.tx_out1["pk_script_bytes"] = struct.pack("<B", len(rtx.tx_out1["pk_script"]))

rtx.tx_out2["value"]        = struct.pack("<Q", 50000)
rtx.tx_out2["pk_script"]    = ("76a914%s88ac" % bob_hashed_pubkey).decode("hex")
rtx.tx_out2["pk_script_bytes"] = struct.pack("<B", len(rtx.tx_out2["pk_script"]))

raw_tx_string = (

    rtx.version
    + rtx.tx_in_count
    + rtx.tx_in["txouthash"]
    + rtx.tx_in["tx_out_index"]
    + rtx.tx_in["scrip_bytes"]
    + rtx.tx_in["script"]
    + rtx.tx_in["sequence"]
    + rtx.tx_out_count

    + rtx.tx_out1["value"]
    + rtx.tx_out1["pk_script_bytes"]
    + rtx.tx_out1["pk_script"]
    + rtx.tx_out2["value"]
    + rtx.tx_out2["pk_script_bytes"]
    + rtx.tx_out2["pk_script"]
    + rtx.lock_time
    + struct.pack("<L", 1)

    )

hashed_tx_to_sign = hashlib.sha256(hashlib.sha256(raw_tx_string).digest()).digest()
# print(hashed_tx_to_sign)

#sk = ecdsa.SigningKey.from_string(Bob_private_key.decode("hex"), curve = ecdsa.SECP256k1)
#vk = sk.verifying_key
print(bitcoin.privkey_to_pubkey(Bob_private_key))

vk = bitcoin.privkey_to_pubkey(Bob_private_key)
public_key = ('\04' + vk).encode("hex")

#signature = sk.sign_digest(hashed_tx_to_sign, sigencode = ecdsa.util.sigencode_der_canonize)
signature = (bitcoin.ecdsa_sign(hashed_tx_to_sign, Bob_private_key))



sigscript = (

    signature
    + "\01"
    + struct.pack("<B", len(public_key.decode("hex")))
    + public_key.decode("hex")

    )

real_tx = (
    rtx.version
    + rtx.tx_in_count
    + rtx.tx_in["txouthash"]
    + rtx.tx_in["tx_out_index"]
    + struct.pack("<B", len(sigscript) + 1)
    + struct.pack("<B", len(signature) + 1)
    + sigscript
    + rtx.tx_in["sequence"]
    + rtx.tx_out_count
    + rtx.tx_out1["value"]
    + rtx.tx_out1["pk_script_bytes"]
    + rtx.tx_out1["pk_script"]
    + rtx.tx_out2["value"]
    + rtx.tx_out2["pk_script_bytes"]
    + rtx.tx_out2["pk_script"]
    + rtx.lock_time

    )

print(real_tx.encode("hex")    )
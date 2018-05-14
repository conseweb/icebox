var bitcore = require('bitcore');

// input: privkey, destAddr, amount, srcTxId, srcTxIdx,
// Create a Transaction
var privateKey = new bitcore.PrivateKey('L1uyy5qTuGrVXrmrsvHWHgVzW9kKdrp27wBC7Vs6nZDTF2BRUVwy');
var utxo = {
    "txId": "115e8f72f39fad874cfab0deed11a80f24f967a84079fb56ddf53ea02e308986",
    "outputIndex": 0,
    "address": "17XBj6iFEsf8kzDMGQk5ghZipxX49VXuaV",
    "script": "76a91447862fe165e6121af80d5dde1ecb478ed170565b88ac",
    "satoshis": 50000
};

var transaction = new bitcore.Transaction()
    .from(utxo)
    .to('1Gokm82v6DmtwKEB8AiVhm82hyFSsEvBDK', 15000)
    .sign(privateKey);

var txSerialized = transaction.serialize(true);
console.log(txSerialized);

// 01000000   : 4-byte version field
// 01         : 1-byte varint specifying the number of inputs
// 8689302ea03ef5dd56fb7940a867f924 0fa811eddeb0fa4c87ad9ff3728f5e11  : 32-byte input tx hash (reverse order)
// 00000000   : 4-byte source transaction index (counting from zero)
// 6b483045022100d20e7f324bcaa66c7c59c5f2e24391da38d298b6ed4e29627978c03e1430620a022069e53eeee1358150bcc39b70f7b9666deda2ec22f352cbf76c15fe4b3f77aead0121029f50f51d63b345039a290c94bffd3180c99ed659ff6ea6b1242bca47eb93b59ff
// fffffff
// 01         : 1-byte varint , number of outputs
// 983a000000000000
// 19 76 a9 14 ad618cf4333b3b248f9744e8e81db2964d0ae397 88 ac
// 00000000

// from: https://bitcoin.stackexchange.com/questions/32628/redeeming-a-raw-transaction-step-by-step-example-required
// private key in WIF: 5HvofFG7K1e2aeWESm5pbCzRHtCSiZNbfLYXBvxyA57DhKHV4U3
// private key in hex: 0ecd20654c2e2be708495853e8da35c664247040c00bd10b9b13e5e86e6a808d
//
// 01000000     : 4-bytes version
// 01           : 1-byte varint, number of inputs
// be66e10da854e7aea9338c1f91cd489768d1d6d7189f586d7a3613f2a24d5396
// 00000000     : 4-bytes source transaction index (counting from zero)
// 19 76 a9 14 dd6cce9f255a8cc17bda8ba0373df8e861cb866e 88 ac
// ffffffff     : 4-bytes
// 01           : 1-byte varint, number of outputs
// 23ce010000000000     : 8-bytes amount of satoshis (64 bit integer, little-endian)
// 19 76 a9 14 a2fd2e039a86dbcf0e1a664729e09e8007f89510 88 ac
// 00000000
// 01000000


// signed tx
// 01000000
// 01
// be66e10da854e7aea9338c1f91cd4897 68d1d6d7189f586d7a3613f2a24d5396  : 32-bytes
// 00000000
// 8c
// 49
// 3046022100cf4d7571dd47a4d47f5cb767d54d6702530a3555726b27b6ac56117f5e7808fe0221008cbb42233bb04d7f28a715cf7c938e238afde90207e9d103dd9018e12cb7180e 01
// 41   dec=65
// 042daa93315eebbe2cb9b5c3505df4c6fb6caca8b756786098567550d4820c09db988fe9997d049d687292f815ccd6e7fb5c1b1a91137999818d17c73d0f80aef9
// ffffffff
// 01
// 23ce010000000000     : 8-bytes amount satoshis
// 19   : Txout-script length = 25
// 76 a9 14 a2fd2e039a86dbcf0e1a664729e09e8007f89510 88 ac
// 00000000

// createrawtransaction [{\"txid\":\"ee33588fced298248c9e693b4eee72e2aae6963381b63cf5850ba2e94abe2d90\",\"vout\":0}] {\"165fbdntWGih7i9mfs9v5ZHgGyNxhHS4Wb\":0.00600000}

// 01000000
// 01
// 902dbe4ae9a20b85f53cb6813396e6aae272ee4e3b699e8c2498d2ce8f5833ee
// 00000000
// 00
// ffffffff
// 01 c027090000000000
// 19 76 a9 14 37ba8314fcd8bbbf49ed9a1d6d27f9797e7d60f1 88 ac
// 00000000

// from : https://stackoverflow.com/questions/38152663/bitcoin-how-to-build-raw-transaction
// Raw transaction in Hex:
//
// 01000000
// 01
// e34ac1e2baac09c366fce1c2245536bda8f7db0f6685862aecf53ebd69f9a89c
// 00000000
// 00
// ffffffff
// 02                   : 1-byte varint, number of outputs
// a025260000000000   : 8-bytes amount
// 19 76 a9 14 d90d36e98f62968d2bc9bbd68107564a156a9bcf 88 ac
// 5062250000000000   : 8-bytes amount
// 19 76 a9 14 07bdb518fa2e6089fd810235cf1100c9c13d1fd2 88 ac
// 00000000           : lock time


//
// VERSION                                 01000000
// TX_IN COUNT [var_int]:                  hex=03, decimal=3
// TX_IN[0]
// TX_IN[0] OutPoint hash (char[32])     94FAE0AC28792796063F23F4A4BA4F977A9599D1579C5AAE7CE6DDA4F8A6B1BB
// TX_IN[0] OutPoint index (uint32_t)    hex=14040000, reversed=00000414, decimal=1044
// TX_IN[0] Script Length (var_int)      hex=19, decimal=25
// TX_IN[0] Script Sig (uchar[])         76A914A438060482FCD835754EA4518C70CC2085AF48FA88AC
// TX_IN[0] Sequence (uint32_t)          FFFFFFFF
// TX_IN[1]
// TX_IN[1] OutPoint hash (char[32])     A3E719B12275357B15FC5DECD9088A0964FE860D49F026F2152E71F681AC3FA4
// TX_IN[1] OutPoint index (uint32_t)    hex=31040000, reversed=00000431, decimal=1073
// TX_IN[1] Script Length (var_int)      hex=19, decimal=25
// TX_IN[1] Script Sig (uchar[])         76A914A438060482FCD835754EA4518C70CC2085AF48FA88AC
// TX_IN[1] Sequence (uint32_t)          FFFFFFFF
// TX_IN[2]
// TX_IN[2] OutPoint hash (char[32])     874CD4C4E1683C43A98A9DAA0926BEA37C10616F165AC35481E8181BFD449C65
// TX_IN[2] OutPoint index (uint32_t)    hex=E0010000, reversed=000001E0, decimal=480
// TX_IN[2] Script Length (var_int)      hex=19, decimal=25
// TX_IN[2] Script Sig (uchar[])         76A914A438060482FCD835754EA4518C70CC2085AF48FA88AC
// TX_IN[2] Sequence (uint32_t)          FFFFFFFF
//
// TX_OUT COUNT                            hex=01, decimal=1
// TX_OUT[0]
// TX_OUT[0] Value (uint64_t)            hex=8038010000000000, reversed_hex=0000000000013880, dec=80000, bitcoin=0.00080000
// TX_OUT[0] PK_Script Length (var_int)  hex=19, dec=25
// TX_OUT[0] pk_script (uchar[])         76A914C2DF275D78E506E17691FD6F0C63C43D15C897FC88AC
// LOCK_TIME                               00000000

// from : https://github.com/gferrin/bitcoin-code/blob/master/makeTransaction.py
// Signed TX:
//      src: 1MMMMSUb1piy2ufrSguNUdFmAcvqrQF8M5
//      dest: 1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa
//
// 01000000
// 01
// 484d40d45b9ea0d652fca8258ab7caa42541eb52975857f96fb50cd732c8b481
// 00000000     : source output index
// 8a           : 1-byte scriptSig len, dec = 138
// 47           : 1-byte sig len + 1, dec=71, hex=142
// 3044022011b5c8f76ac0a63af78da37af0755f7ebb82a96fc66f0d4a471bfe42ccf634a00220304fd275791f8b7c5ecd414577fcf7e8957fc85918dc7b785b1b78db99294ae5 01
// 41           : 1-byte, public key len, dec=65, hex=130
// 0414e301b2328f17442c0b8310d787bf3d8a404cfbd0704f135b6ad4b2d3ee751310f981926e53a6e8c39bd7d3fefd576c543cce493cbac06388f2651d1aacbfcd
// ffffffff     : 4-byte
// 01           : 1-byte varint, number of outputs
// 6264010000000000     : 8-byte, reversed amount
// 19 76 a9 14 c8e90996c7c6080ee06284600c684ed904d14c5c 88 ac
// 00000000

// bad unsigned tx
// 01000000
// 01
// 8f69e09027dc2c02b16bfa51e6670334d34678b7ae31a21bab01ed81258ff53e
// 00000000
// 00
// ffffffff
// 01
// c0e1e400000000000000000000
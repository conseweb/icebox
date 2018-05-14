
// var explorers = require('bitcore-explorers');
var bitcore = require('bitcore');
// var client = new explorers.Insight();

// Generate a address from a SHA256 hash
var value = Buffer.from('correct horse battery staple');
var hash = bitcore.crypto.Hash.sha256(value);
var bn = bitcore.crypto.BN.fromBuffer(hash);

var privateKey = new bitcore.PrivateKey(bn);
var publicKey = privateKey.publicKey;
var address = publicKey.toAddress();
// Import an address via WIF
// var wif = 'Kxr9tQED9H44gCmp6HAdmemAzU3n84H3dGkuWTKvE23JgHMW8gct';
// var address = new bitcore.PrivateKey(wif).toAddress();

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

// client.getUnspentUtxos('address', function(err, utxos) {
//     UTXOs = utxos;
//     console.log('UTXOs:', utxos);
// });

// var transaction = new bitcore.Transaction()
//     .from(utxo)
//     .to(address, amount)
//     .sign(privateKey);


// var utxo = new bitcore.Transaction.UnspentOutput({
//     "txid": "f42af6ab8b4dc3c636c5bfc6ce819063a55060c5619d31a6fa45a36413cb7953",
//     "vout": 0,
//     "address": "2MzuRYCXSHcBDEsSS4rziShvEzWSfoDe2zL",
//     "scriptPubKey": "OP_HASH160 20 0x54025426880aa847ec86f4d2488bbe260bfe0fcb OP_EQUAL",
//     "satoshis": 10000
// });
// var pubs = [
//     "02758b89e56bfa8da41f2c1701aa5927bc026cc3b51bbeff399c53a15f2ae52e28",
//     "02987ab3466118bd3fb5cb0c4fddbdd7ff8e21188314ffed4ecad83fb7689d57d7",
//     "037b7f8cea06cfd5a96023341441b52431e31867c6f3716e5f20be24b709d023eb"
// ];

// var multiSigTx = new bitcore.Transaction()
//     .from(utxo, pubs, 2)
//     .to("n1fqBkX6GtUsaV3EPqjpHcTuWhAQQgKXov", 10000)
//     .fee(5430)
//     .change("2MzuRYCXSHcBDEsSS4rziShvEzWSfoDe2zL")
//     .sign(["083b63f9dbaa100c1714e05a04c20ab32f83f7726ba54a682013a13df6a92949", "5bef634cdcc7f9c2fd2b429d1ddf6cae56923433b6e8b2c5515cf87d84751e0a"]);
// var txSerialized = multiSigTx.serialize(true);
// // Broadcast
// insight.broadcast(txSerialized, function (err, returnedTxId) {
//     if (err) {
//         console.log(err);
//     } else {
//         console.log("Sent coins, tx id is: ");
//         console.log(returnedTxId);
//     }
// });
// var address = bitcore.Address.fromString('2NEvGYDNxcVPZ2ThtmPKYoKBCEa3aJNjPL3');
// var multiSigTx = new bitcore.Transaction()
//     .from(utxo, pubs, 2)
//     .to("mntnnj64W4po96m2ck4GXQJTAiKZQChpWB", 10000)
//     .to("msR1bBwUWjTTNYFU5UTVNCXDUnEx1y2MMQ", 10000)
//     .fee(5430)
//     .change(address)
//     .sign(["7e925007e09447fa6160597391d7a24f8f47e40222d6c94b06bd9cecee5eddff", "6b8adfd22b8dd3186ea5333602b39a59fc1c40c543dc3848ea88c6cd6b738594"]);
// var txSerialized = multiSigTx.serialize(true);
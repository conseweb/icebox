#!/usr/bin/env bash
# In this example we're sending some test bitcoins from an address we control to a brand new test
# address. We'll be sending the coins using the following address, public and private keys (please
# don't abuse).
#  address : mx8hhz3tWjbKkeeTXUyCPUuaJmY9U6SZse
#  public  : 0259c2bd7f9d7d0a8c0b00a1a1124d513f214898638782dfe064b18bd8d7f0bb8c
#  private : 68855a72a1e728d332025f5813ef35e8a6c1a8f5fb43e610c149b782ee290538

# 1. generate a one-shot dummy address we're going to send money to
$ curl -X POST http://api.blockcypher.com/v1/btc/test3/addrs
{
  "private": "6400191867352c57123318dc15875fc0bf8b3104ba9b28a2018a35f6366af71f",
  "public": "0340ac2087db1b455ecb498dc1dbfff5e9977b1a4634a7e6c68e72e666f31d5627",
  "address": "mwWfd7p3NYz7wVqiQCnwkk4WXRCMGqwJqX",
  "wif": "cQw68iYNJeFhcU4x8qs9gP2Aka9s2Q6vL8Lq9XqA3bPetNZziFKC"
}

# 2. build the transaction and save the full output to send.json
$ curl -d '{"inputs": [{"addresses": ["mx8hhz3tWjbKkeeTXUyCPUuaJmY9U6SZse"]}], "outputs": [{"addresses": ["mwWfd7p3NYz7wVqiQCnwkk4WXRCMGqwJqX"], "value": 15000000}]}' http://api.blockcypher.com/v1/btc/test3/txs/new > send.json

# 3. we generate a signature using the above private key and the data provided in the "tosign"
# property of send.json. To do so we use the utility at https://github.com/blockcypher/btcutils/tree/master/signer
# (go build to get binary)
$ ./signer 3debde7315dbc8461338af994ffe4387fa68b2da876f36891a3fe7d6ae54a5dc 68855a72a1e728d332025f5813ef35e8a6c1a8f5fb43e610c149b782ee290538
304402200b0ee21e1d8cbea54b3b414cb5d3d16034ac71b1433bc49852de53c9c017c737022028d8c8fabd01cd822a7bf9e39fd9b1f863943c92494b6c0b2f1e4bac2fb79d0d

# 4. we edit send.json and append the above public key and the newly created signature at the end
# of the file to end up with the following at the bottom of the file (the rest above it is unchanged):
$ tail -n 10 send.json
  "tosign": [
    "e6e59c20e6b7b720ac5e61e82e7eea66ce8b8aadc8beb422b2701869cfae42c2"
  ],
  "signatures": [
    "3044022025812b93f58b3473124ae726c405cac51f39bb89c110e90f77b2f31a2e1fac67022015b8f1c3fa2ce6d0af44f682ed7e1d7933e51d06099c3eaae8725089b7a8a80e"
  ],
  "pubkeys": [
    "03bb318b00de944086fad67ab78a832eb1bf26916053ecd3b14a3f48f9fbe0821f"
  ]
}

# 5. finally, sending the resulting transaction with the signature and the public key
$ curl -d @send.json http://api.blockcypher.com/v1/btc/test3/txs/send > broadcast.json

# This will output the final transaction, including its hash.
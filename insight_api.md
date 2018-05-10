## `GET`

### Transactions by block and address

This endpoint returns full transaction data for blocks and Addresses
> NOTE: there is an undocumented param to paginate, didn't go digging

* [`GET /txs?block={{ .hash }}`](https://github.com/bitpay/insight-api#transactions-by-block)

```json
{
  "pagesTotal": 39,
  "txs": [ {"transaction_details1"}, {"transaction_details2"}, ... ]
}
```
* [`GET /txs?address={{ .address }}`](https://github.com/bitpay/insight-api#transactions-by-address)

```json
{
  "pagesTotal": 1,
  "txs": [ {"transaction_details1"}, {"transaction_details2"} ]
}
```

#### Implementation

- `GET /txs?address`
  * `btcd` Method: `searchrawtransactions`
- `GET /txs?block`
  * `btcd` Method: `getblock` (btcd has a verbose tx option)

### Get Transaction Details

This endpoint returns the full data for a given transaction

* [`GET /tx/:txId`](https://github.com/bitpay/insight-api#transaction)

```json
{
  "txid": "dbaf14e1c476e76ea05a8b71921a46d6b06f0a950f17c5f9f1a03b8fae467f10",
  "version": 1,
  "locktime": 0,
  "vin": [
    {
      "coinbase": "03400d0302ef02062f503253482f522cfabe6d6dd90d39663d10f8fd25ec88338295d4c6ce1c90d4aeb368d8bdbadcc1da3b635801000000000000000474073e03",
      "sequence": 4294967295,
      "n": 0
    }
  ],
  "vout": [
    {
      "value": "50.63517500",
      "n": 0,
      "scriptPubKey": {
        "hex": "4104b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e6537a576782eba668a7ef8bd3b3cfb1edb7117ab65129b8a2e681f3c1e0908ef7bac",
        "asm": "04b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e6537a576782eba668a7ef8bd3b3cfb1edb7117ab65129b8a2e681f3c1e0908ef7b OP_CHECKSIG",
        "addresses": [
          "1MdYC22Gmjp2ejVPCxyYjFyWbQCYTGhGq8"
        ],
        "type": "pubkeyhash"
      },
      "spentTxId": "5c76eb4dfb0941856a229833ef05b2f5c669dadc98ed2a34ea11974cacba9dc7",
      "spentIndex": 0,
      "spentHeight": 201417
    }
  ],
  "blockhash": "000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf",
  "blockheight": 200000,
  "confirmations": 303254,
  "time": 1348310759,
  "blocktime": 1348310759,
  "isCoinBase": true,
  "valueOut": 50.635175,
  "size": 192
}
```

#### Implementation

- `GET /tx/:txId`
  * `btcd` Method: `getrawtransaction`

### Address details

Given an address, return the balance and other details, optionally return the list of `txid` associated

* [`GET /addr/:addrStr/?noTxList=1`](https://github.com/bitpay/insight-api#address)

```json
{
  "addrStr": "1FhNPRh1TxVidoKkWFEpdmK5RXw9vG1KUb",
  "balance": 0,
  "balanceSat": 0,
  "totalReceived": 55.86,
  "totalReceivedSat": 5586000000,
  "totalSent": 55.86,
  "totalSentSat": 5586000000,
  "unconfirmedBalance": 0,
  "unconfirmedBalanceSat": 0,
  "unconfirmedTxApperances": 0,
  "txApperances": 2
}
```

#### Implementation

* `GET /addr/:addrStr/?noTxList=1`
  - `btcd` Method: `searchrawtransactions`
  - Note: Endpoint will modify format of responses

### UTXO details

Fetch a list of UTXO given an address

* [`GET /addrs/:address/utxo`](https://github.com/bitpay/insight-api#unspent-outputs-for-multiple-addresses)

```json
[
  {
    "address": "1BDX1VnPVVvhS6kHQCX4Dpa9zauHj9raRB",
    "txid": "0a2adb164356427ed46758a6c0e9e89614fda2faf2d741598c88eb4f05fa0bbb",
    "vout": 2,
    "scriptPubKey": "76a914700f4c9c534270b41ba885ad44c1929652efa83788ac",
    "amount": 0.00493617,
    "satoshis": 493617,
    "height": 492686,
    "confirmations": 10571
  }
]
```

#### Implementation

* `GET /addrs/:address/utxo`
  - `btcd` Method: `searchrawtransactions`
  - Note: Endpoint will modify format of responses

### Current Exchange Prices

This endpoint is undocumented in the Insight API Docs

* `GET /currency`

```json
{
  "status": 200,
  "data": {
    "bitstamp": 15000
  }
}
```

#### Implementation

* `GET /currency`
  - Insight only implements one exchange right now. We could easily make this more pluggable

### Get block details given block hash

Get block details given the block hash

* [`GET /block/:blockHash`](https://github.com/bitpay/insight-api#block)

```json
{
  "hash": "000000000000000000319a2a35a3ca0ed8b0f72a59beb8bbf7e13039ac47fc88",
  "size": 978216,
  "height": 503252,
  "version": 536870912,
  "merkleroot": "01536676a4e2ee5806b594259b2d5584f4484077017e628a0b8b5992b8883ba6",
  "tx": [
    "af9be29e0d19639234e956f5717a32c0d195af0dac643701bb2c0c29f86865bc",
    "7799f5b660c8ffc54879200632dd83672bfc4865cb15052e4def22eff3dc6aa9",
    ...
  ],
  "time": 1515456523,
  "nonce": 2150682718,
  "bits": "180091c1",
  "difficulty": 1931136454487.7163,
  "chainwork": "000000000000000000000000000000000000000000e38c4c63724d016d9e9313",
  "confirmations": 4,
  "previousblockhash": "0000000000000000000b386bafcbff0da97ddb6e4e24eb94db101004342b519c",
  "nextblockhash": "0000000000000000007cc5e3f0ae181a5cbc6551b60a49144bb200f2bcf74c71",
  "reward": 12.5,
  "isMainChain": true,
  "poolInfo": {}
}
```

#### Implementation

* `GET /block/:blockHash`
  - `btcd` Method: `getblock`

### Block Summaries

Fetch the Block summaries by date.

> NOTE: There appears to be more to this api. It's not returning all the blocks on a given date

* [`GET /blocks?limit={{ .limit }}&blockDate={{ .blockDate }}`](https://github.com/bitpay/insight-api#block-summaries)

```json
{
  "blocks": [
    {
      "height": 503252,
      "size": 978216,
      "hash": "000000000000000000319a2a35a3ca0ed8b0f72a59beb8bbf7e13039ac47fc88",
      "time": 1515456523,
      "txlength": 2923,
      "poolInfo": { }
    }
  ],
  "length": 1,
  "pagination": {
    "next": "2018-01-10",
    "prev": "2018-01-08",
    "currentTs": 1515542399,
    "current": "2018-01-09",
    "isToday": true,
    "more": false
  }
}
```

#### Implementation

* `GET /blocks?limit={{ .limit }}&blockDate={{ .blockDate }}`
  - No obvious method, easy to string together a couple

### Block Hash

Fetch the block hash by block height

* [`GET /block-index/:blockHeight`](https://github.com/bitpay/insight-api#block-index)

```json
{
  "blockHash": "00000000000000000024fb37364cbf81fd49cc2d51c09c75c35433c3a1945d04"
}
```

#### Implementation

* `GET /block-index/:blockHeight`
  - `btcd` Method: `getblockindex`

### Get Diagnostic Info From Node

Get diagnostic info from the BTC node backing this API. Query can be:
- `getInfo`
- `getDifficulty`
- `getBestBlockHash`
- `getLastBlockHash`

* [`GET /status?q={{ .query }}`](https://github.com/bitpay/insight-api#status-of-the-bitcoin-network)

```json
{
  "info": {
    "version": 120100,
    "protocolversion": 70012,
    "blocks": 503251,
    "timeoffset": 0,
    "connections": 8,
    "proxy": "",
    "difficulty": 1931136454487.716,
    "testnet": false,
    "relayfee": 0.00001,
    "errors": "Warning: unknown new rules activated (versionbit 1)",
    "network": "livenet"
  }
}
```

#### Implementation

* `GET /status?q={{ .query }}`
  - `btcd` Method: `getinfo`, `getdifficulty`, `getbestblockhash`

### Get Node Sync Staus

* [`GET /sync`](https://github.com/bitpay/insight-api#historic-blockchain-data-sync-status)

```json
{
  "status": "finished",
  "blockChainHeight": 503251,
  "syncPercentage": 100,
  "height": 503251,
  "error": null,
  "type": "bitcore node"
}
```

#### Implementation

* `GET /sync`
  - `btcd` Method: `getinfo`?
  - May need to check against other nodes?

### Get Node Peer Status

* [`GET /peer`](https://github.com/bitpay/insight-api#live-network-p2p-data-sync-status)
```json
{
  "connected": true,
  "host": "127.0.0.1",
  "port": null
}
```
* `GET /peer`
  - `btcd` Method: `getpeerinfo`

## `POST`

### Verify

Unsure what this endpoint does, undocumented

* `POST /messages/verify`
  - POST Body
```json
{
  "address": "1FhNPRh1TxVidoKkWFEpdmK5RXw9vG1KUb",
  "signature": "a signature",
  "message": "foobar"
}
```
  - Return JSON
```json
{
  "nodata": "nodata"
}
```

### Send Transaction

This endpoint broadcasts a formatted bitcoin transaction

* [`POST /tx/send`](https://github.com/bitpay/insight-api#transaction-broadcasting)
  - POST Body
```json
{
  "rawtx": "01000000017b1eabe0209b1fe794124575ef807057c77ada2138ae4fa8d6c4de0398a14f3f00000000494830450221008949f0cb400094ad2b5eb399d59d01c14d73d8fe6e96df1a7150deb388ab8935022079656090d7f6bac4c9a94e0aad311a4268e082a725f8aeae0573fb12ff866a5f01ffffffff01f0ca052a010000001976a914cbc20a7664f2f69e5355aa427045bc15e7c6c77288ac00000000"
}
```
  - Return JSON
```json
{
  "txid": "c7736a0a0046d5a8cc61c8c3c2821d4d7517f5de2bc66a966011aaa79965ffba"
}
```

#### Implementation

* `POST /tx/send`
  - `btcd` Method: `sendrawtransaction`
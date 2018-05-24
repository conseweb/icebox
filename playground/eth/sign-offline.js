#!/usr/bin/env node
'use strict';

// ethereum: generate signed transactions

const fs        = require('fs');
const rls       = require('readline-sync');
const Accounts  = require('web3-eth-accounts');
const web3utils = require('web3-utils');
const accounts  = new Accounts();

async function main() {
    if (process.argv.length < 6) {
        console.log("usage:\n" +
            "\tsign-offline.js filename recipient amount nonce gasprice\n\n" +
            "\t\t amount is given in ether, gas price is given in gwei");
        process.exit(1);
    }

    let filename  = process.argv[2];
    let recipient = process.argv[3];
    let amount    = web3utils.toWei(process.argv[4], "ether");
    let nonce     = process.argv[5];
    let gasprice  = web3utils.toWei(process.argv[6], "gwei");

    console.log("file %s to %s amount %f eth nonce %d price %f",
        filename, recipient, amount, nonce, gasprice);

    let keystore = await fs.readJson(fs.readFileSync(filename));

    if (!("crypto" in keystore)) {
        // MEW creates capitalized "crypto" property
        // web3 expects it in lowercase
        keystore.crypto = keystore.Crypto;
        delete keystore.Crypto;
    }

    let password  = rls.question('keystore Password? ', { hideEchoBack: true });
    let myaccount = accounts.decrypt(keystore, password);
    let data      = await accounts.signTransaction({
        to: recipient,
        value: amount,
        gas: 21000,
        gasPrice: gasprice,
        nonce: nonce,
        chainId: 1 // mainNet
    }, myaccount.privateKey);
    console.log("signed raw transaction: ", data.rawTransaction);
}

main();
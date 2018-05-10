
import json
import requests
import logging
# import args

logging.captureWarnings(True)

print("Hello User!")

#example address
print("Please input the BTC addres you want to verify:") ,
address = "mx8hhz3tWjbKkeeTXUyCPUuaJmY9U6SZse"

#send request to blockchain.info APIs , will retrieve a JSON document with all the transactions
# https://api.blockcypher.com/v1/btc/test3/addrs/%s/full?limit=50?unspentOnly=true&includeScript=true
resp = requests.get('https://api.blockcypher.com/v1/btc/test3/addrs/%s/full?limit=50?unspentOnly=true&includeScript=true' % address)

# print resp.text

#store the list into utxo_list
utxo_list = json.loads(resp.text)

print utxo_list

print(" ")
# print("FORMAT:") , ("  [ Transaction ID : Index Number - Balance available to spend (in BTC)  ]")
print(" ")

total = 0
total = int(total)
#for each json object in the list of json objects we will now pretty print the important elements
print "Address: %s, %f btc" % (utxo_list['address'],  float(utxo_list['final_balance'])/100000000)
for tx in utxo_list['txs']:
    print "TxHash: %s" % tx['hash']
    for utxo in tx['outputs']:
        #print transactions ID : index number - balance available to spend
        print("%s - %f BTC" % (utxo['addresses'], float(utxo['value']) / 100000000))
        print(" ")


# print("Total BTC available to spend: %f" % (float(total) / 100000000) )
print("------")
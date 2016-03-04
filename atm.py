import requests
import json
import sys # for testing

url = "http://52.90.140.22:5000"
args = {}
args['accountNum'] = "0112345679"
args['password'] = "test3"
#args['challenge'] = "123"
loc = "/getSession"

response = requests.post(url+loc,data=args)
decodedOut = json.loads(response.text)

session = None
if isinstance(decodedOut, dict):
    session = decodedOut['SessionID']
    print session
else:
    print decodedOut
    sys.exit()

args = {}
args['destAccount'] = "0112345678"
args['session'] = session
args['amount'] = "5.4"
loc = "/giveMoney"
response = requests.post(url+loc,data=args)
decodedOut = json.loads(response.text)

if isinstance(decodedOut, dict):
        print decodedOut['Status']
else:
        print decodedOut



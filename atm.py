import requests
import json
import sys # for testing

url = "http://192.168.1.114:5000"
args = {}
args['accountNum'] = "123456781"
args['password'] = "test3"
args['challenge'] = "1234"
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



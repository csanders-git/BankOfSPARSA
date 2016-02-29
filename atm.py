import requests
import json
import sys # for testing

url = "http://52.90.140.22:5000"
args = {}
args['accountNum'] = "123456781"
args['password'] = "test3"
args['challenge'] = "123"
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
args['session'] = session
args['accountNum'] = "0112345679"
loc = "/getPin"

response = requests.post(url+loc,data=args)
decodedOut = json.loads(response.text)
if isinstance(decodedOut, dict):
    pin = decodedOut['Pin']
    print pin
else:
    print decodedOut
    sys.exit()


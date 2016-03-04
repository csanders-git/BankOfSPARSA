import requests
import json
import sys # for testing

url = "http://129.21.82.254:5000"
args = {}
args['accountNum'] = "0112345678"
args['password'] = "test3"
#args['challenge'] = "H`:L]oo$M5"
loc = "/getSession"
response = requests.post(url+loc,data=args)
decodedOut = json.loads(response.text)

session = None
if isinstance(decodedOut, dict):
    session = decodedOut['SessionID']
else:
    print decodedOut
    sys.exit()

args = {}
args['accountNum'] = "0112345678"
args['session'] = session
loc = "/getBalance"
response = requests.post(url+loc,data=args)
decodedOut = json.loads(response.text)

if isinstance(decodedOut, dict):
	print decodedOut['Balance']
else:
	print decodedOut    


args = {}
args['accountNum'] = "0112345678"
args['password'] = "test3"
args['session'] = session
args['newPassword'] = "test3"
loc = "/changePassword"
response = requests.post(url+loc,data=args)

decodedOut = json.loads(response.text)

if isinstance(decodedOut, dict):
	print decodedOut['Status']
else:
	print decodedOut 

args = {}
args['accountNum'] = "0112345678"
args['destAccount'] = "0112345678"
args['session'] = session
args['amount'] = "108"
loc = "/transferMoney"
response = requests.post(url+loc,data=args)
decodedOut = json.loads(response.text)

if isinstance(decodedOut, dict):
	print decodedOut['Status']
else:
	print decodedOut

# Pay Bill
args = {}
args['accountNum'] = "0112345678"
args['destAccount'] = "123456781"
args['session'] = session
args['amount'] = "1234"
args['payBill'] = "1"
loc = "/transferMoney"
response = requests.post(url+loc,data=args)
decodedOut = json.loads(response.text)

if isinstance(decodedOut, dict):
	print decodedOut['Status']
else:
	print decodedOut

args = {}
args['accountNum'] = "0112345678"
args['session'] = session
args['newPin'] = "1235"
args['pin'] = "1234"
loc = "/changePin"
response = requests.post(url+loc,data=args)
decodedOut = json.loads(response.text)

if isinstance(decodedOut, dict):
	print decodedOut['Status']
else:
	print decodedOut    



args = {}
args['accountNum'] = "0112345678"
args['session'] = session
loc = "/wasBillPaid"
response = requests.post(url+loc,data=args)
decodedOut = json.loads(response.text)

if isinstance(decodedOut, dict):
	print decodedOut['Status']
else:
	print decodedOut    

    

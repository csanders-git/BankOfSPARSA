import requests
import json
import sys # for testing
from flask import Flask, render_template,request


app = Flask(__name__)


def makeRequest(url2,params):
	url = "http://129.21.82.254:5000"
	loc = url2
	response = requests.post(url+loc,data=params)
	print response.text
	decodedOut = json.loads(response.text)
	session = None
	if isinstance(decodedOut, dict):
	    try:
	        session = decodedOut['SessionID']
            except KeyError:
                 return decodedOut
	    return ("Session",session)
	else:
	    return decodedOut


@app.route("/")
def hello():
    return render_template('index.html')

@app.route("/submitRequest",methods=['POST'])
def parse():
	argsSession = {}
	argsSession['accountNum'] = "123456781"
	ID = int(request.form["reqID"])
	if(ID == 1):
		argsSession['password'] = str(request.form["Password"])
		argsSession['challenge'] = str(request.form["Challenge"])
		out = makeRequest("/getSession",argsSession)
		session = ""
		if(len(out) == 2):
			if(out[0] == "Session"):
				session = out[1]
		print session
		if(session==""):
			return '<button onclick="history.go(-1);">Go back</button><br>' + str(decodedOut)
		args = {}
		args['destAccount'] = str(request.form["AccountNum"])
		args['session'] = session
		args['amount'] = str(request.form["Amount"])
		out = makeRequest("/giveMoney",args)
		return '<button onclick="history.go(-1);">Go back</button><br>' + str(out)
	if(ID == 2):
		argsSession['password'] = str(request.form["Password"])
		argsSession['challenge'] = str(request.form["Challenge"])
		out = makeRequest("/getSession",argsSession)
		session = ""
		if(len(out) == 2):
			if(out[0] == "Session"):
				session = out[1]
		print session
		if(session==""):
			return '<button onclick="history.go(-1);">Go back</button><br>' + str(decodedOut)
		args = {}
		# Source Account
		args['accountNum'] = str(request.form["AccountNum"])
		args['session'] = session
		args['destAccount'] = argsSession['accountNum']
		args['amount'] = str(request.form["Amount"])
		out = makeRequest("/transferMoney",args)
		return '<button onclick="history.go(-1);">Go back</button><br>' + str(out)
	if(ID == 3):
		argsSession['password'] = str(request.form["Password"])
		argsSession['challenge'] = str(request.form["Challenge"])
		out = makeRequest("/getSession",argsSession)
		session = ""
		if(len(out) == 2):
			if(out[0] == "Session"):
				session = out[1]
		print session
		if(session==""):
			return '<button onclick="history.go(-1);">Go back</button><br>' + str(decodedOut)
		args = {}
		# Source Account
		args['accountNum'] = str(request.form["AccountNum"])
		args['session'] = session
		args['destAccount'] = argsSession['accountNum']
		args['newPassword'] = str(request.form["newPassword"])
		out = makeRequest("/changePassword",args)
		return '<button onclick="history.go(-1);">Go back</button><br>' + str(out)
	if(ID == 4):
		argsSession['password'] = str(request.form["Password"])
		argsSession['challenge'] = str(request.form["Challenge"])
		out = makeRequest("/getSession",argsSession)
		session = ""
		if(len(out) == 2):
			if(out[0] == "Session"):
				session = out[1]
		print session
		if(session==""):
			return '<button onclick="history.go(-1);">Go back</button><br>' + str(decodedOut)
		args = {}
		args['accountNum'] = str(request.form["AccountNum"])
		args['session'] = session
		args['destAccount'] = argsSession['accountNum']
		args['pin'] = "0000"
		args['newPin'] = str(request.form["newPin"])
		out = makeRequest("/changePin",args)
		return '<button onclick="history.go(-1);">Go back</button><br>' + str(out)
	if(ID == 5):
		argsSession['password'] = str(request.form["Password"])
		argsSession['challenge'] = str(request.form["Challenge"])
		out = makeRequest("/getSession",argsSession)
		session = ""
		if(len(out) == 2):
			if(out[0] == "Session"):
				session = out[1]
		print session
		if(session==""):
			return '<button onclick="history.go(-1);">Go back</button><br>' + str(decodedOut)
		args = {}
		args['accountNum'] = str(request.form["AccountNum"])
		args['session'] = session
		args['destAccount'] = argsSession['accountNum']
		out = makeRequest("/getBalance",args)
		return '<button onclick="history.go(-1);">Go back</button><br>' + str(out)
 	return "Unknown Request"


if __name__ == "__main__":
	app.run(host="localhost", port=5001,debug=True)

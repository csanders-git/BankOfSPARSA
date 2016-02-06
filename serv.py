from flask import Flask, render_template,request
import random, math, json
import time
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError # For sql error catching
import hashlib
import sys # for testing




app = Flask(__name__)
app.config.from_pyfile('hello.cfg')
db = SQLAlchemy(app)
db.create_all()


class Users(db.Model):
    uid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(512))
    team = db.Column(db.Integer)
    #email = db.Column(db.String(120), unique=True)

    def __init__(self, username, email):
        self.username = username
        self.password = password

    def __repr__(self):
    	return '<User %r>' % (self.username)
        #return '<User %r>' % self.

class Session(db.Model):
    __tablename__ = 'Session'
    session = db.Column(db.String(128), primary_key=True)
    time = db.Column(db.Float(), unique=True)
    ip = db.Column(db.String(255), unique=True)

    def __init__(self, session=None, time=None, ip=None):
        self.session = session
        self.time = time
        self.ip = ip

    def __repr__(self):
    	return '<Session %r>' % (self.session)

# Returns None if not valid otherwise the result object
def checkSession(sessionId,time2,remoteIP):
	# Expire all sessions that are too old
	result = Session.query.filter(time2 > Session.time).all()
	for sessionRecord in result:
		try:
			db.session.delete(sessionRecord)
			db.session.commit()
		except IntegrityError:
			return None
	result = Session.query.filter(Session.session == sessionId, Session.ip == remoteIP).first()
	return result


def writeLogMessage(number,message,data):
	message = {'Error Number':number, 'Error Message':message, 'Error X-Data':data, 'Time':time.time()}
	message_string = json.dumps(message)
	outputLoc = app.config['LOG_OUTPUT']
	outputLoc = outputLoc.split('|')
	if('stdout' in outputLoc):
		print message_string
	print 'file' in outputLoc
	if('file' in outputLoc):
		# We could also supoprt a JSON handler here to say ES
		try:
			myfile = open(app.config['ERROR_LOG'], "a")
		except IOError:
			return None
		try:
			myfile.write(message_string+"\n")
		except IOError:
			return None
		finally:
			myfile.close()

@app.route("/")
def hello():
	users = Users.query.all()
	
	return "hello" + str(users)
    #return render_template('index.html')

# Takes a username if it is a white team it will
# provide trigger the second factor gen
@app.route("/getSecondFactor",methods=['GET','POST'])
def secondFactor():
	validRequest = False
	# Get the username and password
	if request.method == 'POST':
		required = ["username"]
		for param in required: 
			if param in request.form.keys():
				continue
			else:
				writeLogMessage(1,"The required arguments were not provided", str(request.form.keys()))
				return json.dumps("Error 01: We were unable to process your request")
		if(len(request.form["username"]) != 0):
			username = request.form["username"]
			result = Users.query.filter(Users.username == username).first()
			print result.username
		else:
			writeLogMessage(2,"There was an issue getting the username value", "")
			return json.dumps("Error 02: We were unable to process your request")
	return json.dumps("test")
# Takes a username and password, if white team additional
@app.route("/getSession",methods=['GET','POST'])
def session():
	validRequest = False
	# Get the username and password
	if request.method == 'POST':
		requestTime = time.time()
		remote_ip = request.remote_addr
		required = ["username","password"]
		# Check if we got our required params
		for param in required: 
			if param in request.form.keys():
				continue
			else:
				writeLogMessage(4,"The required arguments were not provided", str(request.form.keys()))
				return json.dumps("Error 04: We were unable to process your request")
		if(len(request.form["username"]) != 0  and len(request.form["password"]) != 0):
			username = request.form["username"]
			password = request.form["password"]
			# hash our password with two salts
			m = hashlib.sha512()
			m.update(app.config['SECRET_KEY'])
			m.update(password)
			m.update(username)
			password = m.hexdigest()
			# Test if our user and password are valid
			result = Users.query.filter(Users.username == username, Users.password == password).first()
			if(str(result.username) == username):
					validRequest = True
			else:
				writeLogMessage(6,"An invalid username and password combination was provided",username)
				return json.dumps("Error 06: We were unable to process your request")
		else:
			writeLogMessage(5,"Either the username or password was blank","")
			return json.dumps("Error 05: We were unable to process your request")
	else:
		writeLogMessage(3,"We received an invalid method",request.method)
		return json.dumps("Error 03: We were unable to process your request")
	if(validRequest == True):
		# Use the os.urandom() function to create a CSPRNG
		try:
			rng = random.SystemRandom()
		except NotImplementedError:
			writeLogMessage(2,"The random number generator was not available","")
			return json.dumps("Error 02: We were unable to process your request")
		sessionID = ""
		# We have 93 possible options and 128 slots (or 93^128 combinations)
		for i in range(0,128):
			sessionID += chr(rng.randint(33, 126))
		# Make sure we got a string of the length we expected
		if(sessionID == "" or len(sessionID) != 128):
			writeLogMessage(1,"The sessionID we generated was not the right length",sessionID)
			return json.dumps("Error 01: We were unable to process your request")
		# Persist the SessionID with the IP Address
		# We only allow 5 seconds for the user to use the session
		u = Session(sessionID,requestTime+app.config['SESSION_TIMEOUT'],remote_ip)
		try:
			db.session.add(u)
			db.session.commit()
		except IntegrityError as e:
			writeLogMessage(9,"There was an issue inserting our value, perhaps a non-unique sessionID",e)
			return json.dumps("Error 09: We were unable to process your request")
		# Check session will remove old keys here and make sure we're valid
		valid = checkSession(sessionID,requestTime,remote_ip)
		if(valid == None):
			writeLogMessage(8,"The session was not added properly, check MySQL","")
			return json.dumps("Error 08: We were unable to process your request")
		# Return the SessionID to the user
		data = { 'SessionID': sessionID }
		encoded_data = json.dumps(data)
		return encoded_data
	else:
		writeLogMessage(7,"We never set the validRequest flag, uhoh","")
		return json.dumps("Error 07: We were unable to process your request")

# Takes a session, an account, and an amount
@app.route("/giveMoney",methods=['POST'])
def giveMoney():
	tempSession = ["1234"]
	tempIPs = ["127.0.0.1"]
	tempAccounts = ["1234"]
	if request.method == 'GET':
		remote_ip = request.remote_addr
		required = ["session","destAccount","amount"]
		# Check if we got our required params
		for param in required:
			if param in request.form.keys():
				continue
			else:
				return "Error 100: We were unable to process your request"
		# Check that we have a valid session ID
		
		if(len(request.form["session"]) != 0):
			valid = checkSession(request.form["session"],time.time(),remote_ip)
			if(valid != None):
				print valid.session
				session = valid.session
			else:
				print "The session identifier provided expired or was invalid"
				return "Error 101: We are unable to process your request"
		else:
				return "Error 102: We are unable to process your request"
		# Check if our amount is valid
		try:
			amount = float(request.form["amount"])
		except ValueError:
			return "Error 103: We are unable to process your request"
		if(amount < 0 or amount > 99999):
			return "Error 104: We are unable to process your request"
		# Check if our account is valid
		try:
			destAccount = int(request.form["destAccount"])
		except ValueError:
			return "Error 105: We are unable to process your request"
		if str(destAccount) not in tempAccounts:
			return "Error 106: We are unable to process your request"
		# Get the existing amount and add ours
		# Return success status
		data = [ { 'Status': "Completed" } ]
		encoded_data = json.dumps(data)
		return encoded_data	

# Takes a session, an account, and an amount
@app.route("/takeMoney",methods=['GET'])
def takeMoney():
	tempSession = ["1234"]
	tempIPs = ["127.0.0.1"]
	tempAccounts = ["1234"]
	if request.method == 'GET':
		remote_ip = request.remote_addr
		required = ["session","srcAccount","amount"]
		# Check if we got our required params
		for param in required:
			if param in request.form.keys():
				continue
			else:
				return "Error 200: We were unable to process your request"
		# Check that we have a valid session ID
		if(len(request.form["session"]) != 0):
			if(request.form["session"] in tempSession) and (remote_ip in tempIPs):
				session = request.form["session"]
			else:
				return "Error 201: We are unable to process your request"
		else:
				return "Error 202: We are unable to process your request"
		# Check if our amount is valid
		try:
			amount = float(request.form["amount"])
		except ValueError:
			return "Error 203: We are unable to process your request"
		if(amount < 0 or amount > 99999):
			return "Error 204: We are unable to process your request"
		# Check if our account is valid
		try:
			srcAccount = int(request.form["srcAccount"])
		except ValueError:
			return "Error 205: We are unable to process your request"
		if str(srcAccount) not in tempAccounts:
			return "Error 206: We are unable to process your request"
		# Get the existing amount and add ours
		# Return success status
		data = [ { 'Status': "Completed" } ]
		encoded_data = json.dumps(data)
		return encoded_data

# Takes a session, an account, and an amount
@app.route("/transferMoney",methods=['GET'])
def transferMoney():
	tempSession = ["1234"]
	tempIPs = ["127.0.0.1"]
	tempAccounts = ["1234","1235"]
	if request.method == 'GET':
		remote_ip = request.remote_addr
		required = ["session","srcAccount","destAccount","amount"]
		# Check if we got our required params
		for param in required:
			if param in request.form.keys():
				continue
			else:
				print "We did not receive the expected parameters"
				return "Error 300: We were unable to process your request"
		# Check that we have a valid session ID
		if(len(request.form["session"]) != 0):
			if(request.form["session"] in tempSession) and (remote_ip in tempIPs):
				session = request.form["session"]
			else:
				print "Either the sessionID was invalid or the remote_IP was invalid"
				return "Error 301: We are unable to process your request"
		else:
				print "The session provided was of length 0"
				return "Error 302: We are unable to process your request"
		# Check if our amount is valid
		try:
			amount = float(request.form["amount"])
		except ValueError:
			print "We could not convert the amount to a float"
			return "Error 303: We are unable to process your request"
		if(amount < 0 or amount > 99999):
			print "The amount provided was either too large or too small"
			return "Error 304: We are unable to process your request"
		# Check if our source account is valid
		try:
			srcAccount = int(request.form["srcAccount"])
		except ValueError:
			print "We could not convert srcAccount to an integer"
			return "Error 305: We are unable to process your request"
		if str(srcAccount) not in tempAccounts:
			print "We could not locate the provided srcAccount"
			return "Error 306: We are unable to process your request"
		# Check if our dest account is valid
		try:
			destAccount = int(request.form["destAccount"])
		except ValueError:
			print "We could not convert destAccount to an integer"
			return "Error 307: We are unable to process your request"
		if str(destAccount) not in tempAccounts:
			print "We could not locate the provided destAccount"
			return "Error 308: We are unable to process your request"
		if(srcAccount == destAccount):
			print "The request had the same source and destination accounts"
			return "Error 309 We are unable to process your request"
		# Get the existing amount and add ours
		# Return success status
		data = [ { 'Status': "Completed" } ]
		encoded_data = json.dumps(data)
		return encoded_data


if __name__ == "__main__":
	app.run()

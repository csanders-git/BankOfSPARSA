from flask import Flask, render_template,request
import random, math, json
import time
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError # For sql error catching
from flask_recaptcha import ReCaptcha
import hashlib
import sys # for testing
import smtplib # for email



app = Flask(__name__)
app.config.from_pyfile('hello.cfg')
recaptcha = ReCaptcha(app=app)
db = SQLAlchemy(app)
db.create_all()


class Users(db.Model):
    uid = db.Column(db.Integer, primary_key=True)
    accountNum = db.Column(db.String(10), unique=True)
    password = db.Column(db.String(512))
    team = db.Column(db.Integer)
    secondFactor = db.Column(db.String(255))
    challenge = db.Column(db.String(10))

    def __init__(self, accountNum, password, team, challenge):
        self.accountNum = accountNum
        self.password = password
        self.team = team
        self.challenge = challenge

    def __repr__(self):
    	return '<User %r>' % (self.accountNum)

class Session(db.Model):
    __tablename__ = 'session'
    uid = db.Column(db.Integer,primary_key=True)
    session = db.Column(db.String(128), unique=True)
    time = db.Column(db.Float())
    ip = db.Column(db.String(255))

    def __init__(self, uid=None, session=None, time=None, ip=None):
        self.uid = uid
        self.session = session
        self.time = time
        self.ip = ip

class Accounts(db.Model):
    __tablename__ = 'accounts'
    uid = db.Column(db.Integer,primary_key=True)
    balance = db.Column(db.Float())
    pin = db.Column(db.Integer())

    def __init__(self, uid=None, balance=None,pin=None):
        self.uid = uid
        self.balance = balance
        self.pin = pin

# Returns None if not valid otherwise the result object
def checkSession(uid,sessionId,time2,remoteIP):
	# Expire all sessions that are too old
        # This is a hack because .all() doesn't return right elements
        while(Session.query.filter(time2>Session.time).count() != 0):
            result = Session.query.filter(time2 > Session.time).first()
            Session.query.filter(Session.session == result.session).delete()
        try:
            db.session.commit()
        except IntegrityError:
		return None
        result = Session.query.filter(Session.uid == uid, Session.session == sessionId, Session.ip == remoteIP).first()
	return result


def writeLogMessage(number,message,data):
	message = {'Error Number':number, 'Error Message':message, 'Error X-Data':data, 'Time':time.time()}
	message_string = json.dumps(message)
	outputLoc = app.config['LOG_OUTPUT']
	outputLoc = outputLoc.split('|')
	if('stdout' in outputLoc):
		print message_string
	if('file' in outputLoc):
		# We could also supoprt a JSON handler here to say ES
		try:
			myfile = open(app.config['ERROR_LOG'], "a")
		except IOError:
			return json.dumps("Error 00: We are unable to process your request")
		try:
			myfile.write(message_string+"\n")
		except IOError:
			return json.dumps("Error 00: We are unable to process your request")
		finally:
			myfile.close()
        return json.dumps("Error " + str(number) + ": We are unable to process your request")

def hashPass(password,accountNum):
    # hash our password with two salts
    m = hashlib.sha512()
    m.update(app.config['SECRET_KEY']) # Static Salt
    m.update(password)
    m.update(accountNum) # Dynamic Salt
    password = m.hexdigest()
    return password


@app.route("/")
def hello():
    return "Welcome"
#    return render_template('index.html')

@app.route("/humanTest",methods=['GET','POST'])
def human():
	print request.form.keys()
	if('accountNum' in request.form.keys()):
		userCheck= request.form["accountNum"]
	elif('accountNum' in request.args.keys()):
		userCheck= request.args["accountNum"]
	else:
		userCheck = ""
	return render_template('captcha.html',username=userCheck)

#Takes a accountNum and session
@app.route("/getBalance",methods=['GET','POST'])
def retBalance():
    remote_ip = request.remote_addr
    required = ["accountNum","session"]
    # Check if we got our required params
    for param in required: 
        if param in request.form.keys():
            continue
        else:
            return writeLogMessage(501,"The required arguments were not provided", str(request.form.keys()))
    accountNum = request.form["accountNum"]
    result = Users.query.filter(Users.accountNum == accountNum).first()
    if(result==None):
        return writeLogMessage(505,"An invalid accountNum was provided",accountNum)
    valid = False
    # Check if we got our required params
    if(len(request.form["session"]) != 0):
        valid = checkSession(result.uid,request.form["session"],time.time(),remote_ip)
        if(valid != None):
            valid = True
        else:
            return writeLogMessage(502,"The session identifier provided expired or was invalid", request.form["session"])
    else:
            return writeLogMessage(503,"The session param provided was empty","")
    if valid == True:
        resAccount = Accounts.query.filter(Accounts.uid == result.uid).first()
        print resAccount.balance
        data = { 'Balance': resAccount.balance }
        encoded_data = json.dumps(data)
        return encoded_data
    else:
        writeLogMessage(504,"Somehow we got an invalid request, this shouldn't happen", "")
        return json.dumps("Error: 504: We were unable to process your request")
 
   # Get the balance information for our user
# Takes a accountNum if it is a white team it will
# provide trigger the second factor gen
@app.route("/getSecondFactor",methods=['GET','POST'])
def secondFactor():
	if not recaptcha.verify():
		print request.form.keys()
		writeLogMessage(406,"The user did not pass the reCaptcha challenge","")
		return json.dumps("Error 406: We were unable to process your request")
	validRequest = False
	# Get the accountNum and password
	if request.method == 'POST':
		required = ["accountNum"]
		for param in required: 
			if param in request.form.keys():
				continue
			else:
				writeLogMessage(401,"The required arguments were not provided", str(request.form.keys()))
				return json.dumps("Error 401: We were unable to process your request")
		if(len(request.form["accountNum"]) != 0):
			accountNum = request.form["accountNum"]
			result = Users.query.filter(Users.accountNum == accountNum).first()
			if result!=None:
				print result.secondFactor
				#Generate random challenge
				# Use the os.urandom() function to create a CSPRNG
				try:
					rng = random.SystemRandom()
				except NotImplementedError:
					writeLogMessage(403,"The random number generator was not available","")
					return json.dumps("Error 403: We were unable to process your request")
				secret = ""
				# We have 93 possible options and 128 slots (or 93^10 combinations)
				for i in range(0,10):
					secret += chr(rng.randint(33, 126))
				# If we got a valid user then attach the secret and email them
				result.challenge=secret
				print secret
				try:
					db.session.commit()
				except IntegrityError as e:
					writeLogMessage(404,"There was an issue inserting our value, perhaps a non-unique sessionID",e)
					return json.dumps("Error 404: We were unable to process your request")
				# Generate the email
				#sender = 'from@fromdomain.com'
				#receivers = ['to@todomain.com']
				#message = "Subject: SMTP e-mail test\nThis is a test e-mail message."
				#try:
				#   smtpObj = smtplib.SMTP('localhost')
				#   smtpObj.sendmail(sender, receivers, message)         
				#   print "Successfully sent email"
				#except SMTPException:
				#   print "Error: unable to send email"
			else:
				return writeLogMessage(405,"No result was returned for that accountNum",accountNum)
		else:
			return writeLogMessage(402,"There was an issue getting the accountNum value", "")
	return json.dumps("test")

# Takes a accountNum, session, old password, and new password
@app.route("/changePassword",methods=['POST'])
def changePass():
    # Get the accountNum and password
    remote_ip = request.remote_addr
    required = ["accountNum","password","session","newPassword"]
    # Check if we got our required param
    for param in required:
        if param in request.form.keys():
            continue
        else:
            return writeLogMessage(600,"The required arguments were not provided", str(request.form.keys()))
    accountNum = request.form["accountNum"]
    password = request.form["password"]
    password = hashPass(password,accountNum)
    #TODO: If Whiteteam skip password check
    # Veryify old password is correct with username and get uid
    valid = False
    result = Users.query.filter(Users.accountNum == accountNum, Users.password == password).first()
    if(result==None):
        return writeLogMessage(601,"An invalid or incorrect username or old password was provided","")
    if(len(request.form["session"]) != 0):
        valid = checkSession(result.uid,request.form["session"],time.time(),remote_ip)
        if(valid != None):
            valid = True
        else:
            return writeLogMessage(602,"The session identifier provided expired or was invalid", request.form["session"])
    else:
            return writeLogMessage(603,"The session param provided was empty","")
    # Generate our new password hash
    newPass = hashPass(request.form["newPassword"],accountNum)
    # Check that the old password does not match the new password
    if(password == newPass):
        return writeLogMessage(604,"The new password is the same as the old password or a collision occured",[newPass,password]) 
    #TODO: Password complexity
    # They have a valid session, keep going
    if valid == True:
        # Update new password
        result.password = newPass
        #TODO Catch exception
        db.session.commit()
        # Return success status
        data = [ { 'Status': "Completed" } ]
        encoded_data = json.dumps(data)
        return encoded_data
    else:
        return writeLogMessage(604,"We should never have gotten here, there was an invalid request","")




# Takes a accountNum and password, if white team additional challenge
@app.route("/getSession",methods=['POST'])
def session():
    validRequest = False
    # Get the accountNum and password
    remote_ip = request.remote_addr
    required = ["accountNum","password"]
    # Check if we got our required params
    for param in required: 
        if param in request.form.keys():
            continue
        else:
            return writeLogMessage(4,"The required arguments were not provided", str(request.form.keys()))
    # Make sure our parameters aren't empty
    if(len(request.form["accountNum"]) != 0  and len(request.form["password"]) != 0):
        accountNum = request.form["accountNum"]
        password = request.form["password"]
        # hash our password with two salts
        password = hashPass(password,accountNum)        
        print password
        # Test if our user and password are valid
        result = Users.query.filter(Users.accountNum == accountNum, Users.password == password).first()
        if(result != None and result.accountNum == accountNum):
                validRequest = True
        else:
            return writeLogMessage(6,"An invalid accountNum and password combination was provided",accountNum)
    else:
         return writeLogMessage(5,"Either the accountNum or password was blank","")
    # Check if we need an additional authentication because they're white team
    #  White team is team 0
    if result.team == 0:
        if 'challenge' in request.form.keys():
            if(result.challenge == None):
                return writeLogMessage(13,"User forgot to reaquire 2nd factor after using it",result.accountNum)
            if(request.form["challenge"] == result.challenge):
                # Reset challenge
                result.challenge=None
                try:
                    db.session.commit()
                except IntegrityError as e:
                    return writeLogMessage(12,"There was an issue inserting our value, perhaps a non-unique sessionID",e)
                print "we maid it"
            else:
                writeLogMessage(10,"The challenge provided was incorrect","")
                return json.dumps("Error 10: We were unable to process your request")
        else:
            writeLogMessage(11,"The user is a white teamer but didn't provide a challenge","")
            return json.dumps("Error 11: We were unable to process your request")
    # If it wasn't white team or we passed white team checks then:
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
        u = Session(result.uid,sessionID,time.time()+app.config['SESSION_TIMEOUT'],remote_ip)
        try:
            db.session.add(u)
            db.session.commit()
        except IntegrityError as e:
            writeLogMessage(9,"There was an issue inserting our value, perhaps a non-unique sessionID",e)
            return json.dumps("Error 09: We were unable to process your request")
        print "Added our Session"
        # Check session will remove old keys here and make sure we're valid
        valid = checkSession(result.uid,sessionID,time.time(),remote_ip)
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
			valid = checkSession(1,request.form["session"],time.time(),remote_ip)
			if(valid != None):
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
@app.route("/takeMoney",methods=['POST'])
def takeMoney():
	tempSession = ["1234"]
	tempIPs = ["127.0.0.1"]
	tempAccounts = ["1234"]
	if request.method == 'POST':
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
@app.route("/transferMoney",methods=['POST'])
def transferMoney():
	tempSession = ["1234"]
	tempIPs = ["127.0.0.1"]
	tempAccounts = ["1234","1235"]
	if request.method == 'POST':
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
	app.run(host='172.30.0.251')

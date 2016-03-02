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
WHITETEAM = 0
ATM = -1


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
        # Check what team the uid associated with the session is on
        res1 = Session.query.filter(Session.session == sessionId, Session.ip == remoteIP).first()
        if(res1 == None):
            return None
        res2 = Users.query.filter(Users.uid==res1.uid).first()
        if(res2 == None):
            return None
        team = res2.team
        # Whiteteam may need a session even though they are modifying non-whiteteam uid's (don't check UIDs)
        if(team==WHITETEAM or team==ATM):
            result = Session.query.filter(Session.session == sessionId, Session.ip == remoteIP).first()
        else:
            result = Session.query.filter(Session.uid == uid, Session.session == sessionId, Session.ip == remoteIP).first()
        # Check if our query returned nothing
        if result == None:
            return None
	else:
            return (result,team)


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

# It doesn't seem like hashlib throws any exceptions
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
@app.route("/getPin",methods=['GET','POST'])
def retPin():
    remote_ip = request.remote_addr
    required = ["accountNum","session"]
    # Check if we got our required params
    for param in required: 
        if param in request.form.keys():
            continue
        else:
            return writeLogMessage(900,"The required arguments were not provided", str(request.form.keys()))
    accountNum = str(request.form["accountNum"])
    # Get tentative uid for account number
    res1 = Users.query.filter(Users.accountNum == accountNum).first()
    if res1 == None:
        return WriteLogMessage(907,"An invalid account number was supplied","")

    valid = False
    if(len(request.form["session"]) != 0):	
        # if it's white team UID is not a factor, it just must be a valid session/IP combo
        valid = checkSession(res1.uid,str(request.form["session"]),time.time(),remote_ip)
	print valid
        if valid == None:
            return writeLogMessage(902,"The session identifier provided expired or was invalid", request.form["session"])
    else:
        return writeLogMessage(903,"The session param provided was empty","")
    # If white team good to go
    if(valid[1] != ATM):
        return writeLogMessage(904,"Someone other than the ATM requested a pin","")
    else:
        valid = True
    if valid == True:
        resAccount = Accounts.query.filter(Accounts.uid == res1.uid).first()
        data = { 'Pin': resAccount.pin }
        encoded_data = json.dumps(data)
        return encoded_data
    else:
        return writeLogMessage(905,"Somehow we got an invalid request, this shouldn't happen", "")

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
    accountNum = str(request.form["accountNum"])
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
    remote_ip = request.remote_addr
    required = ["accountNum","session","newPassword"]
    # Check if we got our required param (for nonwhite-we also need passwordOld)
    for param in required:
        if param in request.form.keys():
            continue
        else:
            return writeLogMessage(600,"The required arguments were not provided", str(request.form.keys()))
    accountNum = str(request.form["accountNum"])
    # Generate our new password hash
    print request.form["newPassword"]
    newPass = hashPass(str(request.form["newPassword"]),accountNum)
    # Get tentative uid for account number
    res1 = Users.query.filter(Users.accountNum == accountNum).first() 
    if res1 == None:
        return WriteLogMessage(607,"An invalid account number was supplied","")
    # Check if we have a valid session
    if(len(request.form["session"]) != 0):
        # if it's white team UID is not a factor, it just must be a valid session/IP combo
        valid = checkSession(res1.uid,str(request.form["session"]),time.time(),remote_ip)
        if valid == None:
            return writeLogMessage(602,"The session identifier provided expired or was invalid", request.form["session"])
    else:
        return writeLogMessage(603,"The session param provided was empty","")
    # If white team skip old password req
    if(valid[1] != WHITETEAM):
        if 'password' not in request.form.keys():
            return WriteLogMessage(606,"The request was non-white team and featured no old password","")
        # we'll use this more general for as our result
        password = str(request.form["password"])
        password = hashPass(password,accountNum)
        # Verify old password is correct with accountNum and get uid
        result = Users.query.filter(Users.accountNum == accountNum, Users.password == password).first()
        if(result==None):
            return writeLogMessage(601,"An invalid or incorrect username or old password was provided","")
        # Check that the old password does not match the new password
        if(password == newPass):
            return writeLogMessage(604,"The new password is the same as the old password or a collision occured",[newPass,password])
        #TODO: Password complexity
    else:
        result = Users.query.filter(Users.accountNum == accountNum).first()
        if result == None:
            return writeLogMessage(608,"An invalid username was required, but we should have never gotten here","")
    # They have a valid session, keep going
    # Update new password
    result.password = newPass
    try:
        db.session.commit()
    except IntegrityError as e:
        return writeLogMessage(605, "We had an issue updating our password, with the DB",str(e))
    # Return success status
    data = [ { 'Status': "Completed" } ]
    encoded_data = json.dumps(data)
    return encoded_data


# Takes a accountNum, session, old password, and new password
@app.route("/changePin",methods=['POST'])
def changePin():
    remote_ip = request.remote_addr
    required = ["accountNum","session","pin","newPin"]
    # Check if we got our required param (for nonwhite-we also need passwordOld)
    for param in required:
        if param in request.form.keys():
            continue
        else:
            return writeLogMessage(800,"The required arguments were not provided", str(request.form.keys()))
    accountNum = str(request.form["accountNum"])
    newPin = str(request.form["newPin"])
    # Get tentative uid for account number
    res1 = Users.query.filter(Users.accountNum == accountNum).first() 
    if res1 == None:
        return WriteLogMessage(807,"An invalid account number was supplied","")
    # Check if we have a valid session
    if(len(request.form["session"]) != 0):
        # if it's white team UID is not a factor, it just must be a valid session/IP combo
        valid = checkSession(res1.uid,str(request.form["session"]),time.time(),remote_ip)
        if valid == None:
            return writeLogMessage(802,"The session identifier provided expired or was invalid", request.form["session"])
    else:
        return writeLogMessage(803,"The session param provided was empty","")
    # If white team skip old password req
    if(valid[1] != WHITETEAM):
        if 'pin' not in request.form.keys():
            return WriteLogMessage(806,"The request was non-white team and featured no old pin","")
        pin = str(request.form["pin"])
        # Verify old password is correct with accountNum and get uid
        result = Accounts.query.filter(Accounts.uid == res1.uid, Accounts.pin == pin).first()
        if(result==None):
            return writeLogMessage(801,"An invalid or incorrect account number or old pin was provided","")
        # Check that the old password does not match the new password
        if(pin == newPin):
            return writeLogMessage(804,"The new pin is the same as the old pin",[newPin,pin])
    else:
        result = Accounts.query.filter(Accounts.uid == res1.uid).first()
        if result == None:
            return writeLogMessage(608,"An invalid username was required, but we should have never gotten here","")
    if(len(newPin) != 4):
        return writeLogMessage(609,"An invalid pin was provided, the pin wasn't long enough","") 
    # Update new pin
    result.pin = newPin
    try:
        db.session.commit()
    except IntegrityError as e:
        return writeLogMessage(605, "We had an issue updating our password, with the DB",str(e))
    # Return success status
    data = [ { 'Status': "Completed" } ]
    encoded_data = json.dumps(data)
    return encoded_data



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
        accountNum = str(request.form["accountNum"])
        password = str(request.form["password"])
        # hash our password with two salts
        password = hashPass(password,accountNum)        
        print password # This is usful for setup
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
    if result.team == WHITETEAM:
        if 'challenge' in request.form.keys():
            if(result.challenge == None):
                return writeLogMessage(13,"User forgot to reaquire 2nd factor after using it",result.accountNum)
            if(str(request.form["challenge"]) == result.challenge):
                pass
                #TODO reenable when done testing
                # Reset challenge to ntohing
                #result.challenge=None
                #try:
                #    db.session.commit()
                #except IntegrityError as e:
                #    return writeLogMessage(12,"There was an issue inserting our value, perhaps a non-unique sessionID",e)
            else:
                return writeLogMessage(10,"The challenge provided was incorrect","")
        else:
            return writeLogMessage(11,"The user is a white teamer but didn't provide a challenge","")
    # If it wasn't white team or we passed white team checks then:
    if(validRequest == True):
        # Use the os.urandom() function to create a CSPRNG
        try:
            rng = random.SystemRandom()
        except NotImplementedError:
            return writeLogMessage(2,"The random number generator was not available","")
        sessionID = ""
        # We have 93 possible options and 128 slots (or 93^128 combinations)
        for i in range(0,128):
            sessionID += chr(rng.randint(33, 126))
        # Make sure we got a string of the length we expected
        if(sessionID == "" or len(sessionID) != 128):
            return writeLogMessage(1,"The sessionID we generated was not the right length",sessionID)
        # Persist the SessionID with the IP Address
        # We only allow N seconds for the user to use the session
        u = Session(result.uid,sessionID,time.time()+app.config['SESSION_TIMEOUT'],remote_ip)
        try:
            db.session.add(u)
            db.session.commit()
        except IntegrityError as e:
            return writeLogMessage(9,"There was an issue inserting our value, perhaps a non-unique sessionID",e)
        # Check session will remove old keys here and make sure we're valid
        valid = checkSession(result.uid,sessionID,time.time(),remote_ip)
        if(valid == None):
            return writeLogMessage(8,"The session was not added properly, check MySQL","")
        # Return the SessionID to the user
        data = { 'SessionID': sessionID }
        encoded_data = json.dumps(data)
        return encoded_data
    else:
       return writeLogMessage(7,"We never set the validRequest flag, uhoh","")
    

# This is for whiteteam only
# Takes a session, an account, and an amount
@app.route("/giveMoney",methods=['POST'])
def giveMoney():
    remote_ip = request.remote_addr
    required = ["session","destAccount","amount"]
    # Check if we got our required params
    for param in required:
        if param in request.form.keys():
	    continue
	else:
	    return writeLogMessage(100,"The correct parameters were not provided","")
    accountNum = str(request.form["destAccount"])
    # Check that we have a valid session ID
    if(len(request.form["session"]) != 0):
        valid = checkSession(-1,str(request.form["session"]),time.time(),remote_ip)
        if(valid == None):
            return writeLogMessage(101,"The session identifier provided expired or was invalid",str(request.form["session"]))
        if(valid[1] != WHITETEAM):
            return writeLogMessage(107,"A non white-team member tried to use a white-team only function","")
    else:
        return writeLogMessage(102,"The sessionID provided was blank","")
    # Check if our amount is valid
    try:
	amount = float(str(request.form["amount"]))
    except ValueError:
        return writeLogMessage(103,"We were unable to convert the amount provided to a float",str(request.form["amount"]))
    if(amount < 0 or amount > 99999):
        return writeLogMessage(104,"The amount prescribed was invalid",str(amount))
    # Check if our account is valid
    res1 = Users.query.filter(Users.accountNum == accountNum).first()
    if(res1 == None):
        return writeLogMessage(105,"The account number provided could not be found",str(accountNum))
    res2 = Accounts.query.filter(Accounts.uid == res1.uid).first()
    if(res2 == None):
        return writeLogMessage(106,"The user UID we got did not seem to have account",str(res1.uid))
    res2.balance = res2.balance + amount
    try:
        # Get the existing amount and add ours
        db.session.commit()
    except IntegrityError as e:
        return writeLogMessage(108,"We were unable to update the balance of users",str(e))
    #if valid success status
    data = { 'Status': "Completed" }
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
    remote_ip = request.remote_addr
    required = ["accountNum","session","destAccount","amount"]
    # Check if we got our required params
    for param in required:
        if param in request.form.keys():
            continue
        else:
            return  writeLogMessage(300,"We did not receive the expected parameters",str(request.form.keys()))
    # Get Account number uid
    accountNum = str(request.form["accountNum"])
    destAccount = str(request.form["destAccount"])
    res = Users.query.filter(Users.accountNum == accountNum).first()
    if(res == None):
        return  writeLogMessage(301,"A request to transfer from an unknown account number was supplied",accountNum)
    if(len(request.form["session"]) != 0):
        valid = checkSession(res.uid,str(request.form["session"]),time.time(),remote_ip)
        if(valid == None):
            return writeLogMessage(302,"The session identifier provided expired or was invalid",str(request.form["session"]))
    else:
        return writeLogMessage(303,"The sessionID provided was blank","")
    # Check if our amount is valid
    try:
        amount = float(str(request.form["amount"]))
    except ValueError:
        return writeLogMessage(305,"We were unable to convert the amount provided to a float",str(request.form["amount"]))
    if(amount < 0 or amount > 99999):
        return writeLogMessage(306,"The amount prescribed was invalid",str(amount))
 
    sourceAccountID = res.uid
    dest = Users.query.filter(Users.accountNum == destAccount).first()
    if(dest == None):
        return writeLogMessage(304,"We were unable to find a destination account that matched the provided",destAccount)
    destAccountID = dest.uid
    source = Accounts.query.filter(Accounts.uid == sourceAccountID ).first()
    dest = Accounts.query.filter(Accounts.uid == destAccountID).first()
    if(source.balance - amount < 0):
        return writeLogMessage(307,"The source account does not have adequite funds to make that transfer",accountNum)
    else:
        source.balance = source.balance - amount
        dest.balance = dest.balance + amount
    try:
        db.session.commit()
    except IntegrityError as e:
        return writeLogMessage(308,"We were unable to transfer money due to a SQL issue",str(e))

    data = [ { 'Status': "Completed" } ]
    encoded_data = json.dumps(data)
    return encoded_data
 

if __name__ == "__main__":
	app.run(host='10.0.1.10')

from flask import Flask, redirect, render_template, session, request
from flask_session import Session
import urllib
import pymongo
import pytz
import datetime
import random
from string import digits, ascii_uppercase

app = Flask(__name__)
app.secret_key = "testing"
#app.config["SESSION_PERMANENT"] = False
#app.config["SESSION_TYPE"] = "filesystem"
#Session(app)

@app.route('/')
def menu():
	return render_template('menu.html')
	return 'Hello, World!'

@app.route('/login', methods=['POST', 'GET'])
def login():
    message = 'Please login to your account'
    if "username" in session and session['username'] != None:
        return redirect('/')
    # return render_template('login.html', message=message)
    if hasattr(request, 'method') and request.method == "POST":
        print("inside request")
        username = request.form.get("username")
        password = request.form.get("password")
        # mongo_uri = "mongodb://swaril:" + urllib.parse.quote(
        #     "$w@R!1") + "@ac-ymz3eon-shard-00-00.iympypo.mongodb.net:27017,ac-ymz3eon-shard-00-01.iympypo.mongodb.net:27017,ac-ymz3eon-shard-00-02.iympypo.mongodb.net:27017/?ssl=true&replicaSet=atlas-y20jq1-shard-0&authSource=admin&retryWrites=true&w=majority"
        # client = pymongo.MongoClient(
        #     mongo_uri)
        # db = client.User
        # records = db.cashManagement
        user_found = readDb( "Users" , {"username": username})
        print("user Found" + str(user_found) + username)
        if user_found and "username" in user_found and "password" in user_found:
            username = user_found['username']
            passwordcheck = user_found['password']

            # if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
            if passwordcheck == password:
                print(username)
                session["username"] = username
                session['type'] = user_found['type']
                session['amount'] = user_found['amount']
                return redirect('/')
            else:
                message = 'Wrong password'
                return render_template('login.html', message=message)
        else:
            message = 'Email not found'
            return render_template('login.html', message=message)
    return render_template('login.html', message=message)


def readDb(collection, condition):
    try:
        mongo_uri = "mongodb://swaril:" + urllib.parse.quote(
            "$w@R!1") + "@ac-ymz3eon-shard-00-00.iympypo.mongodb.net:27017,ac-ymz3eon-shard-00-01.iympypo.mongodb.net:27017,ac-ymz3eon-shard-00-02.iympypo.mongodb.net:27017/?ssl=true&replicaSet=atlas-y20jq1-shard-0&authSource=admin&retryWrites=true&w=majority"
        client = pymongo.MongoClient(
            mongo_uri)
        db = client.cashManagement
        records = db[collection]
        cursor = records.find_one(condition)
        return cursor
    except:
        return {'status':'error'}


@app.route("/scanQRdebit")
def scanQRdebit():
    print("HOME session:", session)
    if "username" not in session or ("username" in session and session['username'] == None):
        return render_template("login.html")
    return render_template('scanQRDebit.html')



@app.route("/viewBalanceCredit", methods=["POST", "GET"])
def viewBalance():
    print('viewBalance username:', session['username'], session)
    code = request.args.get('code')
    print(code)
    cursor = readDb('Customers', {"cid": code})
    print(cursor)
    print("END viewBalance")
    if "username" in session and session['username'] != None:
        logged_in = "true"
    return render_template("viewBalance.html", Username=cursor['name'], Balance=cursor['balance'], code=code, logged_in=logged_in, MoneyCollected=session['amount'])



@app.route("/debit", methods=["POST", "GET"])
def debit():
    if "username" not in session or ("username" in session and session['username'] == None):
        return render_template("login.html")
    if hasattr(request, 'method') and request.method == "POST":
        json_req = request.get_json()
        print(json_req)
        cursor = readDb('Customers', {"cid": str(json_req['code'])})
        print('checking paraments',json_req['code'], json_req['amount'])
        # isIntegar = isinstance(json_req['amount'], int)
        # if not isIntegar:
        #     return {'status' : 'error', 'message': 'Invalid Amount'}
        print("Read DB:", cursor)
        final_balance = int(cursor['balance']) - int(json_req['amount'])
        if (final_balance < 0):
            return {'status': 'error', 'message': 'Insufficient Balance'}
        user = readDb('Users', {'username': session['username']})
        if(user) :
            amount_collected = int(user['amount']) + int(json_req['balance'])
        else:
            return {'status': 'error', 'message': "DB issues, try Again!"}
        resp = update_db('Users', {'amount': amount_collected}, {'username' : session['username']})
        print(resp)
        document = {'amount': json_req['amount'], 'cid' : json_req['code'] }
        receipt = generate_debit_receipt(document)

        print("final Balance:", final_balance)
        resp = update_db("Customers", {'balance': final_balance}, {'cid' : str(json_req['code'])})
        print(resp)
        return {'status':'success', 'balance':final_balance, 'amount':json_req['amount'] }
    return {'status': 'error', 'message' : 'Try Again'}



def update_db(collection, document, condition):
    mongo_uri = "mongodb://swaril:" + urllib.parse.quote(
        "$w@R!1") + "@ac-ymz3eon-shard-00-00.iympypo.mongodb.net:27017,ac-ymz3eon-shard-00-01.iympypo.mongodb.net:27017,ac-ymz3eon-shard-00-02.iympypo.mongodb.net:27017/?ssl=true&replicaSet=atlas-y20jq1-shard-0&authSource=admin&retryWrites=true&w=majority"
    client = pymongo.MongoClient(
        mongo_uri)
    db = client.cashManagement
    records = db[collection]
    document = { "$set" : document}
    resp = records.update_one(condition, document)
    print(resp)
    cursor = readDb(collection, condition)
    return cursor


def rand_string(length = 8):
    legals = digits + ascii_uppercase
    return ''.join( random.choice(legals) for _ in range(length) )


def generate_debit_receipt(document):
    if("username" in session):
        document['user'] = session['username']
        document['txn_id'] = 'CT' + rand_string()
        document['time'] = datetime.datetime.now(pytz.timezone('Asia/Kolkata'))
        mongo_uri = "mongodb://swaril:" + urllib.parse.quote(
            "$w@R!1") + "@ac-ymz3eon-shard-00-00.iympypo.mongodb.net:27017,ac-ymz3eon-shard-00-01.iympypo.mongodb.net:27017,ac-ymz3eon-shard-00-02.iympypo.mongodb.net:27017/?ssl=true&replicaSet=atlas-y20jq1-shard-0&authSource=admin&retryWrites=true&w=majority"
        client = pymongo.MongoClient(
            mongo_uri)

        mydb = client["cashManagement"]
        mycol = mydb["debitTransactions"]
        x = mycol.insert_one(document)
        return x;

	

from flask import Flask, redirect, render_template, session, request, Response
#from flask_session import Session
import urllib
import pymongo
import pytz
import datetime
import random
from string import digits, ascii_uppercase
import pandas as pd

import numpy as np
app = Flask(__name__)
app.secret_key = "testing"
#app.config["SESSION_PERMANENT"] = False
#app.config["SESSION_TYPE"] = "filesystem"
#Session(app)
mongo_uri = "mongodb://swaril:" + urllib.parse.quote("$w@R!1") + "@ac-ymz3eon-shard-00-00.iympypo.mongodb.net:27017,ac-ymz3eon-shard-00-01.iympypo.mongodb.net:27017,ac-ymz3eon-shard-00-02.iympypo.mongodb.net:27017/?ssl=true&replicaSet=atlas-y20jq1-shard-0&authSource=admin&retryWrites=true&w=majority"
client = pymongo.MongoClient(mongo_uri)
mydb = client["cashManagement"]

@app.route('/')
def menu():
    # response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    if "username" in session and session['username'] != None:
        if session['type'] == 'superuser' :
            return render_template('menu.html',logged_in = 'true', type=session['type'], MoneyCollected=session['amount'], MoneyDeposited=session['amount_credited'], SecurityAmount = session['security_amount'], username = session['username'])
        else:
            return render_template('menu.html',logged_in = 'true', type=session['type'], MoneyCollected=session['amount'], username = session['username'] )
    return render_template('login.html', message='Please login to your account')


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-store"
    return response

@app.route('/login', methods=['POST', 'GET'])
def login():
    message = 'Please login to your account'
    if "username" in session and session['username'] != None:
        return redirect('/')
    # return render_template('login.html', message=message)
    if hasattr(request, 'method') and request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        print("Login by username:" + str(username) + ' password :' + str(password))
        user_found = readDb( "Users" , {"username": username})
        # user_found = {'username' : 'swaril', 'password' : 'singhal'}
        #print("user Found" + str(user_found) + username)
        if user_found and "username" in user_found and "password" in user_found:
            username = user_found['username']
            passwordcheck = user_found['password']
            if user_found and 'isLoggedIn' in user_found and user_found['isLoggedIn'] == True :
                message = 'User is already Logged in in another device'
                return render_template('login.html', message=message)
            resp = update_db("Users", {'isLoggedIn' : True}, {"username": username})
            
            # if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
            if passwordcheck == password:
                # print(username)
                session["username"] = username
                session['type'] = user_found['type']
                session['amount'] = user_found['amount']
                if(user_found['type'] == 'superuser') :
                    session['amount_credited'] = user_found['amount_credited']
                    session['security_amount'] = user_found['security_amount']
                return redirect('/')
            else:
                message = 'Wrong password'
                return render_template('login.html', message=message)
        else:
            message = 'User not found'
            return render_template('login.html', message=message)
    return render_template('login.html', message=message)


@app.route("/lastTransactions", methods=['POST', 'GET'])
def lastDebitTransactions():
    if "username" not in session or ("username" in session and session['username'] == None):
        return render_template("login.html")
    if request.method == "GET":
        cursor = readTransactions('debitTransactions', {"user": session['username']})
        # if('status' in cursor and cursor['status'] == 'error'):
        #     return cursor
        #print(str(cursor['user']) + str(cursor['cid']))
        print("TRANSACTION:" + str(cursor))
        return render_template('lastTransactions.html', transaction=cursor, title = "Debit Transactions" , logged_in = 'true', username = session['username']  )
        
        return list(cursor)
        return render_template('lastTransactions.html', transactions=list(cursor), title = "Debit Transactions")

@app.route("/lastReturnTransactions", methods=['POST', 'GET'])
def lastReturnTransactions():
    if "username" not in session or ("username" in session and session['username'] == None):
        return render_template("login.html")
    if request.method == "GET":
        cursor = readTransactions('debitTransactions', {"user": session['username'], 'security' : 50})
        # if('status' in cursor and cursor['status'] == 'error'):
        #     return cursor
        #print(str(cursor['user']) + str(cursor['cid']))
        # print("TRANSACTION:" + str(cursor))
        return render_template('lastTransactions.html', transaction=cursor, title = "Return Transactions" , logged_in = 'true', username = session['username']  )
        
        return list(cursor)
        return render_template('lastTransactions.html', transactions=list(cursor), title = "Credit Transactions")


@app.route("/lastCreditTransactions", methods=['POST', 'GET'])
def lastCreditTransactions():
    print("TEST")
    if request.method == "GET":
        print("lastCreditTransactions:" + session['username'])
        cursor = readTransactions('creditTransactions', {"user": session['username']})
        #print(str(cursor['user']) + str(cursor['cid']))
        print("TRANSACTION:" + str(cursor))
        return render_template('lastTransactions.html', transaction=cursor, title = "Credit Transactions", logged_in = "true", username = session['username'] )
        if(cursor['status'] and cursor['status'] == 'error'):
            return cursor


@app.route("/last20Transactions", methods=['POST', 'GET'])
def last20Transactions():
    if request.method == "GET":
        code = int(request.args.get('code'))
        if code is None:
            return {'status': 'error', 'message': "Can't find the User"}   
        try:
            cursor = readDb('Customers', {"cid": code})
        except:
            return {'status':'error', 'message': 'DB read Failed!'}
        cursor = readTransactions('debitTransactions', {"cid": code})
        #print(str(cursor['user']) + str(cursor['cid']))
        cursor = list(cursor)
        print("TRANSACTION:" + str(cursor))
        return render_template('lastTransactions.html', transaction=cursor, title = "Security Deposit Transactions", logged_in = "true", username = session['username'] )
        if(cursor['status'] and cursor['status'] == 'error'):
            return cursor




@app.route("/downloadSecurityDepositRemainingReport")
def downloadSecurityDepositRemainingReport():
    # with open("outputs/Adjacency.csv") as fp:
    #     csv = fp.read()
    records = mydb['Customers']
    # print(records)
    
    cursor = records.find({"security" : 50},{'_id':0})
    # csv = list(csv)
    # df = pd.DataFrame(csv) 
    mongo_docs = list(cursor)
    series_obj = pd.Series({"a key":"a value"})
    series_obj = pd.Series( {"one":"index"} )
    series_obj.index = [ "one" ]

    docs = pd.DataFrame(columns=[])
    for num, doc in enumerate( mongo_docs ):
        doc["cid"] = str(doc["cid"])
        doc_id = doc["cid"]
        series_obj = pd.Series( doc, name=doc_id )
        docs = docs.append( series_obj )
    csv_export = docs.to_csv(sep=",") 
     # CSV delimited by commas
    # print ("\nCSV data:", csv_export) 
    # df.to_csv('GFG.csv') 
    # np.savetxt("GFG.csv", 
    #        csv,
    #        delimiter =", ", 
    #        fmt ='% s')

    # return redirect("/")
    fname = str(session['username'])
    return Response(
        csv_export,
        mimetype="text/json",
        headers={"Content-disposition":
                 "attachment; filename=" + fname + "RemainingSD.csv"})





@app.route("/lastSecurityDepositTransactions", methods=['POST', 'GET'])
def lastSecurityDepositTransactions():
    print("TEST")
    if request.method == "GET":
        print("lastCreditTransactions:" + session['username'])
        cursor = readTransactions('creditTransactions', {"user": session['username'], "security" : 50})
        #print(str(cursor['user']) + str(cursor['cid']))
        cursor = list(cursor)
        print("TRANSACTION:" + str(cursor))
        return render_template('lastTransactions.html', transaction=cursor, title = "Security Deposit Transactions", logged_in = "true", username = session['username'] )
        if(cursor['status'] and cursor['status'] == 'error'):
            return cursor

def readTransactions(collection, condition):
    try:
        
        records = mydb[collection]
        if session['type'] == 'superuser' :
            cursors = records.find(condition, {'Name':1, 'amount':1, 'cid': 1, 'user':1, 'time':1, 'security' : 1, 'Phone_Number':1 }).sort('time',pymongo.DESCENDING).limit(10)
        else:
            cursors = records.find(condition, {'Name': 1, 'amount':1, 'cid': 1, 'user':1, 'txn_id':1, 'time':1, 'Phone_Number':1}).sort('time',pymongo.DESCENDING).limit(10)
        # cursors = records.find_one(condition)
        print("Read Transactions: " + str(cursors))
        return cursors
    except pymongo.errors.OperationFailure:
        print("exception:" + e)
        return {'status':'error'}


@app.route("/returnCard", methods=["POST", "GET"])
def returnCard():
    # print('viewBalance username:', session['username'], session)
    if "username" not in session or ("username" in session and session['username'] == None):
        return render_template("login.html")

    code = int(request.args.get('code'))
    if code is None:
        return {'status': 'error', 'message': "Can't find the User"}   
    try:
        cursor = readDb('Customers', {"cid": code})
    except:
        return {'status':'error', 'message': 'DB read Failed!'}
    # print(cursor)
    # print("END viewBalance")
    
    sum = int(cursor['balance']) + int(cursor['security'])
    return render_template("returnCard.html", Username=cursor['name'], Balance=cursor['balance'], code=code, security = cursor['security'] ,phone_number = cursor['phone_number'], amount = sum, logged_in = "true", username = session['username'] )



@app.route("/viewBalance", methods=["POST", "GET"])
def viewBalance():
    # print('viewBalance username:', session['username'], session)
    if "username" not in session or ("username" in session and session['username'] == None):
        return render_template("login.html")

    code = int(request.args.get('code'))
    if code is None:
        return render_template("viewBalance.html", Username='', Balance='', code=code, MoneyCollected=session['amount'], username = session['username'] )   
    # print(code)
    try:
        cursor = readDb('Customers', {"cid": code})
    except:
        return {'status':'error', 'message': 'DB read Failed!'}
    # print(cursor)
    # print("END viewBalance")
    logged_in = "true"
    return render_template("viewBalance.html", Username=cursor['name'], Balance=cursor['balance'], logged_in=logged_in, code=code, MoneyCollected=session['amount'], username = session['username'] )


@app.route("/view", methods=["POST", "GET"])
def view():
    # print('viewBalance username:', session['username'], session)
    code = request.args.get('code')
    code = int(code[-4:])
    # print(code)
    cursor = readDb('Customers', {"cid": code})
    print(cursor)
    print("END viewBalance")
    if "username" in session and session['username'] != None:
        logged_in = "true"
    return render_template("view.html", Username=cursor['name'], Balance=cursor['balance'], Phone_Number = cursor['phone_number'], code = code)



def readDb(collection, condition):
    try:
        # mongo_uri = "mongodb://swaril:" + urllib.parse.quote(
        #     "$w@R!1") + "@ac-ymz3eon-shard-00-00.iympypo.mongodb.net:27017,ac-ymz3eon-shard-00-01.iympypo.mongodb.net:27017,ac-ymz3eon-shard-00-02.iympypo.mongodb.net:27017/?ssl=true&replicaSet=atlas-y20jq1-shard-0&authSource=admin&retryWrites=true&w=majority"
        # client = pymongo.MongoClient(
        #     mongo_uri)
        # db = client.cashManagement
        records = mydb[collection]
        cursor = records.find_one(condition)
        return cursor
    except:
        return {'status':'error', 'message': 'DB read Failed!'}


@app.route("/scanQRdebit")
def scanQRdebit():
    # response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    print("HOME session:", session)
    if "username" not in session or ("username" in session and session['username'] == None):
        return render_template("login.html")
    return render_template('scanQRDebit.html',  logged_in="true", username = session['username'] )


@app.route("/scanQRcredit")
def scanQRcredit():
    print("HOME session:", session)
    if "username" not in session or ("username" in session and session['username'] == None):
        return render_template("login.html")
    return render_template('scanQRCredit.html', logged_in="true", username = session['username'] )


@app.route("/scanQRreturnCard")
def scanQRreturnCard():
    print("HOME session:", session)
    if "username" not in session or ("username" in session and session['username'] == None):
        return render_template("login.html")
    return render_template('scanQRreturnCard.html', logged_in="true", username = session['username'] )

@app.route("/viewBalanceCredit", methods=["POST", "GET"])
def viewBalanceCredit():
    if "username" not in session or ("username" in session and session['username'] == None):
        return render_template("login.html", message = 'Please Login!')
    code = int(request.args.get('code'))
    # cursor = readDb('Customers', {"cid": code})
    try:
        cursor = mydb.Customers.find_one({"cid": code})
        if cursor is None:
            return {'status' : 'error', 'message' : 'No valid user for this QR code found, Please Try a valid QR code!'}
    except:
        return {'status':'error', 'message': 'DB read Failed!'}
    if "username" in session and session['username'] != None:
        logged_in = "true"
    return render_template("viewBalanceCredit.html", Username=cursor['name'], Balance=cursor['balance'], code=code, logged_in=logged_in, phone_number = cursor['phone_number'], MoneyCollected=session['amount'], MoneyDeposited=session['amount_credited'], type = session['type'], username = session['username'], security_deposit = cursor['security'] )



@app.route("/reset", methods=["POST", "GET"])
def reset():
    print("RESET")
    if "username" not in session or ("username" in session and session['username'] == None):
        return render_template("login.html")
    if hasattr(request, 'method') and request.method == "POST":
        json_req = request.get_json()
        code  = json_req['code']
        cursor = readDb('Customers', {"cid": int(code)})
        if cursor is None:
            return {'status': 'error', 'message' : 'User Not Found'}
        if 'status' in cursor and cursor['status'] == 'error':
            return {'status': 'error', 'message' : 'Try Again!'}
        # print('checking paraments',json_req['code'], json_req['amount'])
        # isIntegar = isinstance(json_req['amount'], int)
        # if not isIntegar:
        #     return {'status' : 'error', 'message': 'Invalid Amount'}
        print("Read DB:", cursor)
        user = readDb('Users', {'username': session['username']})
        if(user) :
            amount_collected = int(session['amount']) + int(cursor['balance'])
        else:
            return {'status': 'error', 'message': "DB issues, try Again!"}
        security_collected =  session['security_amount'] - cursor['security']
        session['security_amount'] = security_collected
        session['amount'] = amount_collected
        resp = update_db('Users', {'amount': amount_collected, 'security_amount' : security_collected}, {'username' : session['username']})
        print(resp)
        document = {'Name':cursor['name'],'amount': cursor['balance'], 'cid' : int(json_req['code']) , 'security' : cursor['security'] , 'Phone_Number': cursor['phone_number']}
        receipt = generate_debit_receipt(document)

        # print("final Balance:", final_balance)
        resp = update_db("Customers", {'balance': 0,'name':'', 'security':0, 'phone_number':''}, {'cid' : int(code)})
        # print(resp)
        return {'status':'success', 'balance':cursor['balance'], 'security':cursor['security'] , 'total_sum' : cursor['balance'] + cursor['security']}
    return {'status': 'error', 'message' : 'Try Again'}


@app.route("/debit", methods=["POST", "GET"])
def debit():
    if "username" not in session or ("username" in session and session['username'] == None):
        return render_template("login.html")
    if hasattr(request, 'method') and request.method == "POST":
        json_req = request.get_json()
        # print(json_req)
        # cursor = readDb('Customers', {"cid": str(json_req['code'])})
        cursor = mydb.Customers.find_one({"cid": int(json_req['code'])})
        if cursor is None:
            return {'status': 'error', 'message' : 'User Not Found'}
        if 'status' in cursor and cursor['status'] == 'error':
            return {'status': 'error', 'message' : 'Try Again!'}
        print('checking paraments',int(json_req['code']), json_req['amount'])
        # isIntegar = isinstance(json_req['amount'], int)
        # if not isIntegar:
        #     return {'status' : 'error', 'message': 'Invalid Amount'}
        # print("Read DB:", cursor)
        final_balance = int(cursor['balance']) - int(json_req['amount'])
        if (final_balance < 0):
            return {'status': 'error', 'message': 'Insufficient Balance'}
        # user = readDb('Users', {'username': session['username']})
        user = mydb.Users.find_one({'username': session['username']})
        if(user) :
            amount_collected = int(session['amount']) + int(json_req['amount'])
        else:
            return {'status': 'error', 'message': "DB issues, try Again!"}
        session['amount'] = amount_collected
        # resp = update_db('Users', {'amount': amount_collected}, {'username' : session['username']})
        resp = mydb.Users.update_one({'username' : session['username']},{ '$set' :{'amount': amount_collected} })
        # print(resp)
        document = {'Name': cursor['name'], 'amount': json_req['amount'], 'cid' : int(json_req['code']), 'Phone_Number':cursor['phone_number'] }
        receipt = generate_debit_receipt(document)

        # print("final Balance:", final_balance)
        resp = mydb.Customers.update_one({'cid' : int(json_req['code'])},{ '$set' :{'balance': final_balance} })
        # resp = update_db("Customers", {'balance': final_balance}, {'cid' : str(json_req['code'])})
        # print(resp)
        return {'status':'success', 'balance':final_balance, 'amount':json_req['amount'] , 'total_amount_debited' : amount_collected}
    return {'status': 'error', 'message' : 'Try Again'}



def update_db(collection, document, condition):
    # mongo_uri = "mongodb://swaril:" + urllib.parse.quote(
    #     "$w@R!1") + "@ac-ymz3eon-shard-00-00.iympypo.mongodb.net:27017,ac-ymz3eon-shard-00-01.iympypo.mongodb.net:27017,ac-ymz3eon-shard-00-02.iympypo.mongodb.net:27017/?ssl=true&replicaSet=atlas-y20jq1-shard-0&authSource=admin&retryWrites=true&w=majority"
    # client = pymongo.MongoClient(
    #     mongo_uri)
    # db = client.cashManagement
    records = mydb[collection]
    document = { "$set" : document}
    resp = records.update_one(condition, document)
    return resp


def rand_string(length = 8):
    legals = digits + ascii_uppercase
    return ''.join( random.choice(legals) for _ in range(length) )


def generate_debit_receipt(document):
    if("username" in session):
        document['user'] = session['username']
        document['txn_id'] = 'CT' + rand_string()
        document['time'] = datetime.datetime.now(pytz.timezone('Asia/Kolkata'))
        document['time'] = document['time'].strftime("%Y-%m-%d %H:%M:%S")
        # mongo_uri = "mongodb://swaril:" + urllib.parse.quote(
        #     "$w@R!1") + "@ac-ymz3eon-shard-00-00.iympypo.mongodb.net:27017,ac-ymz3eon-shard-00-01.iympypo.mongodb.net:27017,ac-ymz3eon-shard-00-02.iympypo.mongodb.net:27017/?ssl=true&replicaSet=atlas-y20jq1-shard-0&authSource=admin&retryWrites=true&w=majority"
        # client = pymongo.MongoClient(
        #     mongo_uri)

        # mydb = client["cashManagement"]
        mycol = mydb["debitTransactions"]
        x = mycol.insert_one(document)
        return x
    else :
        return {'status' : 'error'}


def generate_credit_receipt(document):
    if("username" in session):
        document['user'] = session['username']
        document['txn_id'] = 'CT' + rand_string()
        document['time'] = datetime.datetime.now(pytz.timezone('Asia/Kolkata'))
        document['time'] = document['time'].strftime("%Y-%m-%d %H:%M:%S")
        print(document['time'])
        # mongo_uri = "mongodb://swaril:" + urllib.parse.quote(
        #     "$w@R!1") + "@ac-ymz3eon-shard-00-00.iympypo.mongodb.net:27017,ac-ymz3eon-shard-00-01.iympypo.mongodb.net:27017,ac-ymz3eon-shard-00-02.iympypo.mongodb.net:27017/?ssl=true&replicaSet=atlas-y20jq1-shard-0&authSource=admin&retryWrites=true&w=majority"
        # client = pymongo.MongoClient(
        #     mongo_uri)

        # mydb = client["cashManagement"]
        mycol = mydb["creditTransactions"]
        x = mycol.insert_one(document)
        return x
    else :
        return {'status' : 'error'}



@app.route("/credit", methods=["POST", "GET"])
def credit():
    if "username" not in session or ("username" in session and session['username'] == None):
        return render_template("login.html")
    if hasattr(request, 'method') and request.method == "POST":
        json_req = request.get_json()
        # print("JSON:" + str(json_req))
        # cursor = readDb('Customers', {"cid": str(json_req['code'])})


        ################ READ DB  #########
        
        Cust_coll = mydb['Customers']
        customer = Cust_coll.find_one({"cid": int(json_req['code'])})

        ################
        # print('checking paraments',json_req['code'], json_req['amount'])
        # print("Read DB:", cursor)
        final_balance = int(customer['balance']) + int(json_req['amount'])
        document = {'balance': final_balance, 'name': json_req['name'], 'phone_number': json_req['phone_number']}
        # print("final Balance:", final_balance)
        # resp = update_db("Customers", document, {'cid' : str(json_req['code'])})
        ############ UPDATE CUSTOMERS ########
        security = json_req['security']
        if security == True:
            document = { "$set" : {'balance': final_balance, 'name': json_req['name'], 'phone_number': json_req['phone_number'], 'security' : int(json_req['security_deposit'])}}
        else :
            document = { "$set" : {'balance': final_balance, 'name': json_req['name'], 'phone_number': json_req['phone_number']}}
        resp = Cust_coll.update_one({'cid' : int(json_req['code'])} , document)
        ############################
        # print("UPDATE CUSTOMERS DB:" + str(resp))
        # cursor = readDb('Users', {"username": str(session['username'])})
        ############ READ USERS ########
        User_coll = mydb['Users']
        cursor = User_coll.find_one({"username": str(session['username'])})
        ############################

        total_amount = int(cursor['amount_credited']) + int(json_req['amount'])
        # resp = update_db("Users", {'amount_credited' : total_amount}, {"username": str(session['username'])})

        ############ UPDATE USERS ########
        if security == True:
            session['security_amount'] = int(session['security_amount']) + int(json_req['security_deposit'])
            document = { "$set" : {'amount_credited' : total_amount, 'security_amount' : session['security_amount']}}
        else :
            document = { "$set" : {'amount_credited' : total_amount}}
        resp = User_coll.update_one({"username": str(session['username'])} , document)
        ############################
        # print("UPDATE USERS DB:" + str(resp))
        # document = {'amount': json_req['amount'], 'cid' : json_req['code'] }
       
        # print("CREATE RECEIPT:" + str(receipt))
        print("CURSOR:" + str(customer))
        session['amount_credited'] = total_amount
        if security == True:
            document = {'Name':customer['name'], 'cid' : int(json_req['code']), 'amount': json_req['amount'],'balance':final_balance,'amount_credited':total_amount, 'Phone_Number': customer['phone_number'], 'security': int(json_req['security_deposit']), 'status':'success' }
        else:
            document = {'Name': customer['name'], 'cid' : int(json_req['code']), 'amount': json_req['amount'],'balance':final_balance,'amount_credited':total_amount, 'Phone_Number': customer['phone_number'], 'security':0,  'status':'success' }
        receipt = generate_credit_receipt(document)
        return {'amount': json_req['amount'],'balance':final_balance,'amount_credited':total_amount, 'cid' : int(json_req['code']), 'status':'success' }
    return {'status': 'error'}

@app.route("/downloadCreditReport")
def downloadCreditReport():
    # with open("outputs/Adjacency.csv") as fp:
    #     csv = fp.read()
    records = mydb['creditTransactions']
    # print(records)
    
    cursor = records.find({"user": session['username']}, {'_id':1,'amount':1, 'cid': 1, 'user':1, 'txn_id':1, 'time':1})
    # csv = list(csv)
    # df = pd.DataFrame(csv) 
    mongo_docs = list(cursor)
    series_obj = pd.Series({"a key":"a value"})
    series_obj = pd.Series( {"one":"index"} )
    series_obj.index = [ "one" ]

    docs = pd.DataFrame(columns=[])
    for num, doc in enumerate( mongo_docs ):
        doc["_id"] = str(doc["_id"])
        doc_id = doc["_id"]
        series_obj = pd.Series( doc, name=doc_id )
        docs = docs.append( series_obj )
    csv_export = docs.to_csv(sep=",") 
     # CSV delimited by commas
    # print ("\nCSV data:", csv_export) 
    # df.to_csv('GFG.csv') 
    # np.savetxt("GFG.csv", 
    #        csv,
    #        delimiter =", ", 
    #        fmt ='% s')

    # return redirect("/")
    fname = str(session['username'])
    return Response(
        csv_export,
        mimetype="text/json",
        headers={"Content-disposition":
                 "attachment; filename=" + fname + "creditTransactions.csv"})



@app.route("/downloadDebitReport")
def downloadDebitReport():
    # with open("outputs/Adjacency.csv") as fp:
    #     csv = fp.read()
    records = mydb['debitTransactions']
    # print(records)

    if session['type'] == 'superuser' :
        cursor = records.find({"user": session['username']}, {'_id':1,'amount':1, 'cid': 1, 'user':1, 'txn_id':1, 'time':1, 'security' :1})
    else :
        cursor = records.find({"user": session['username']}, {'_id':1,'amount':1, 'cid': 1, 'user':1, 'txn_id':1, 'time':1})
    # csv = list(csv)
    # df = pd.DataFrame(csv) 
    mongo_docs = list(cursor)
    series_obj = pd.Series({"a key":"a value"})
    series_obj = pd.Series( {"one":"index"} )
    series_obj.index = [ "one" ]

    docs = pd.DataFrame(columns=[])
    for num, doc in enumerate( mongo_docs ):
        doc["_id"] = str(doc["_id"])
        doc_id = doc["_id"]
        series_obj = pd.Series( doc, name=doc_id )
        docs = docs.append( series_obj )
    csv_export = docs.to_csv(sep=",") 
     # CSV delimited by commas
    # print ("\nCSV data:", csv_export) 
    # df.to_csv('GFG.csv') 
    # np.savetxt("GFG.csv", 
    #        csv,
    #        delimiter =", ", 
    #        fmt ='% s')

    # return redirect("/")
    fname = str(session['username'])
    return Response(
        csv_export,
        mimetype="text/json",
        headers={"Content-disposition":
                 "attachment; filename=" + fname + "debitTransactions.csv"})


@app.route("/downloadSecurityDepositReport")
def downloadSecurityDepositReport():
    # with open("outputs/Adjacency.csv") as fp:
    #     csv = fp.read()
    records = mydb['creditTransactions']
    # print(records)
    
    cursor = records.find({"user": session['username'], "security" : 50}, {'_id':1,'amount':1, 'cid': 1, 'user':1, 'txn_id':1, 'time':1, 'security':1})
    # csv = list(csv)
    # df = pd.DataFrame(csv) 
    mongo_docs = list(cursor)
    series_obj = pd.Series({"a key":"a value"})
    series_obj = pd.Series( {"one":"index"} )
    series_obj.index = [ "one" ]

    docs = pd.DataFrame(columns=[])
    for num, doc in enumerate( mongo_docs ):
        doc["_id"] = str(doc["_id"])
        doc_id = doc["_id"]
        series_obj = pd.Series( doc, name=doc_id )
        docs = docs.append( series_obj )
    csv_export = docs.to_csv(sep=",") 
     # CSV delimited by commas
    # print ("\nCSV data:", csv_export) 
    # df.to_csv('GFG.csv') 
    # np.savetxt("GFG.csv", 
    #        csv,
    #        delimiter =", ", 
    #        fmt ='% s')

    # return redirect("/")
    fname = str(session['username'])
    return Response(
        csv_export,
        mimetype="text/json",
        headers={"Content-disposition":
                 "attachment; filename=" + fname + "creditTransactions.csv"})




@app.route("/logout")
def logout():

    resp = mydb.Users.update_one({"username": session['username']},{'$set':{'isLoggedIn' : False}})
    session["username"] = None
    return redirect("/")
	

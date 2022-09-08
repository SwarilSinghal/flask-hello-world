from flask import Flask, redirect, render_template, session, request
from flask_session import Session
import pymongo
app = Flask(__name__)
app.secret_key = "testing"
#app.config["SESSION_PERMANENT"] = False
#app.config["SESSION_TYPE"] = "filesystem"
#Session(app)

@app.route('/')
def menu():
	return render_template('menu.html')
	return 'Hello, World!'

@app.route('/login', methods=['POST'])
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
        # print("user Found" + email_found)
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
	

from flask import Flask, render_template, request, redirect, abort, session, url_for
from cryptography.fernet import Fernet
import bcrypt
from os.path import exists
from pysondb import db

app = Flask(__name__)
port = 80
app.secret_key = 'cXnLGENNDzinXoRCGuPrAvKYVfMNsOV'
key = b'M_JHq44ttWZ5JpM6ppF3WeEHrpJc9W82b8Ax6tl31wA='
database = db.getDb("data/accounts.json")
f = Fernet(key)

# Funtion to encrypt the password
def encrypt(message):
    data = f.encrypt(message.encode()).decode('utf-8')
    return data

# Function to decrypt the password
def decrypt(message):
    data = f.decrypt(message.encode()).decode('utf-8')
    return data

# Funtion to get all accounts then decrypt the password
def getDBandDecryptPassword(query = None):
    if query == None:
        accounts = database.getAll()
    else:
        accounts = database.getByQuery(query)
    data = []
    for x in accounts:
        to_append = {
            'id': x['id'],
            'website': x['website'],
            'username': x['username'],
            'password': decrypt(x['password'])
        }
        data.append(to_append)
    return data


@app.route('/', methods=['GET', 'POST'])
def login():
    if exists('data/key'):
        if request.method == 'POST':
            password = request.form['masterPassword']
            if bcrypt.checkpw(password.encode(), open('data/key', 'r').read().encode()):
                session['logged_in'] = True
                return redirect('/home')
            else:
                return render_template('login.html', error='incorrectKey')
        else:
            return render_template('login.html')
    else:
        return render_template('register.html')

@app.route('/home', methods=['GET'])
def home():
    session['error'] = ''
    if session['logged_in']:
        # Get all accounts then decrypt the password
        if request.args.get('username') != None and request.args.get('website') != None and request.args.get('username') != '' and request.args.get('website') != '':
            data = {
                'username': request.args.get('username'),
                'website': request.args.get('website'),
            }
            data = getDBandDecryptPassword()
            if len(data) == 0:
                return render_template('home.html', data='noAccount')
            else:
                return render_template('home.html', data=data)

        # search for username and decrypt the password
        elif request.args.get('username') != None and request.args.get('username') != '':
            data = {
                'username': request.args.get('username'),
            }
            data = getDBandDecryptPassword(data)
            if len(data) == 0:
                return render_template('home.html', data='noAccount')
            else:
                return render_template('home.html', data=data)
        # search for website and decrypt the password
        elif request.args.get('website') != None and request.args.get('website') != '':
            data = {
                'website': request.args.get('website'),
            }
            data = getDBandDecryptPassword(data)
            if len(data) == 0:
                return render_template('home.html', data='noAccount')
            else:
                return render_template('home.html', data=data)
        else: 
            data = getDBandDecryptPassword()
            if len(data) == 0:
                return render_template('home.html', data='noAccount')
            else:
                return render_template('home.html', data=data)
    else:
        return redirect('/')

@app.route('/api/logout')
def logout():
    session['logged_in'] = False
    return redirect('/')

@app.route('/api/delete', methods=['GET'])
def deleteAccount():
    if session['logged_in']:
        id = request.args.get('id')
        database.deleteById(id)
        return redirect('/home')
    else:
        return redirect('/')

@app.route('/api/add' , methods=['POST'])
def addAccount():
    if session['logged_in']:
        username = request.form['username']
        website = request.form['website']
        password = request.form['password']
        password = encrypt(password)
        data = {
            'username': username,
            'website': website,
            'password': password
        }
        database.add(data)
        return redirect('/home')
    else:
        return redirect('/')

@app.route('/api/setup/create_masterpass', methods=['POST'])
def createMasterPassword():
    if exists('data/key') == True:
        return 'key exist'
    else:
        if request.form['masterpassword'] != request.form['masterpasswordretype']:
            session['error'] = 'passwordsDontMatch'
            return redirect('/')

        elif request.form['masterpassword'] == request.form['masterpasswordretype'] and len(request.form['masterpassword']) < 8:
            session['error'] = 'passwordTooShort'
            return redirect('/')

        elif request.form['masterpassword'] == request.form['masterpasswordretype'] and len(request.form['masterpassword']) >= 8:
            password = request.form['masterpassword']
            password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            with open('data/key', 'w') as f:
                f.write(password.decode('utf-8'))
            session['logged_in'] = True
            return redirect('/home')

if __name__ == '__main__':
    try:    
        app.run(port=port, host='0.0.0.0', debug=False)
    except PermissionError:
        print('You need root to run this script')
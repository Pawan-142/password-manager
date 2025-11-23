from flask import Flask, render_template, request, redirect, session
import firebase_admin
from firebase_admin import credentials, firestore
import hashlib

app = Flask(__name__)
app.secret_key = 'a8f3e7d2c9b1a4f6e8d5c7b2a3f9e4d1c8b7a6f2e9d3c4b5a7f8e6d9c2b1a4f3'

# Load Firebase service account
cred = credentials.Certificate('firebase_config.json')
firebase_admin.initialize_app(cred)

# Initialize Firestore
db = firestore.client()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/')
def home():
    if 'user' in session:
        return redirect('/dashboard')
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed = hash_password(password)
        
        try:
            users_ref = db.collection('users')
            users = users_ref.where('email', '==', email).where('password', '==', hashed).get()
            
            if users:
                user = users[0]
                session['user'] = user.id
                session['email'] = email
                return redirect('/dashboard')
            
            return render_template('login.html', error='Invalid email or password')
        except Exception as e:
            print("Login Error:", str(e))
            return render_template('login.html', error='Login failed. Please try again.')
    return render_template('login.html', error=None)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        fullname = request.form['fullname']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            return render_template('signup.html', error='Passwords do not match')
        
        if len(password) < 6:
            return render_template('signup.html', error='Password must be at least 6 characters')
        
        hashed = hash_password(password)
        
        try:
            users_ref = db.collection('users')
            existing_users = users_ref.where('email', '==', email).get()
            
            if existing_users:
                return render_template('signup.html', error='Email already exists')
            
            new_user = users_ref.add({
                'fullname': fullname,
                'email': email,
                'password': hashed
            })
            
            session['user'] = new_user[1].id
            session['email'] = email
            session['fullname'] = fullname
            return redirect('/dashboard')
        except Exception as e:
            print("Signup Error:", str(e))
            return render_template('signup.html', error=f'Signup failed: {str(e)}')
    return render_template('signup.html', error=None)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')
    
    user_id = session['user']
    user_email = session.get('email', 'User')
    
    try:
        passwords_ref = db.collection('passwords').where('user_id', '==', user_id).stream()
        passwords_data = {}
        
        for pwd in passwords_ref:
            passwords_data[pwd.id] = pwd.to_dict()
        
        return render_template('dashboard.html', passwords=passwords_data, user_email=user_email)
    except Exception as e:
        print("Dashboard Error:", str(e))
        return render_template('dashboard.html', passwords={}, user_email=user_email)

@app.route('/add_password', methods=['POST'])
def add_password():
    if 'user' not in session:
        return redirect('/login')
    
    user_id = session['user']
    site_name = request.form['site_name']
    username = request.form['username']
    password = request.form['password']
    
    data = {
        'user_id': user_id,
        'siteName': site_name,
        'username': username,
        'password': password
    }
    
    db.collection('passwords').add(data)
    return redirect('/dashboard')

@app.route('/delete_password/<password_id>', methods=['POST'])
def delete_password(password_id):
    if 'user' not in session:
        return redirect('/login')
    
    db.collection('passwords').document(password_id).delete()
    return redirect('/dashboard')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
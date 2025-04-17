from flask import Flask, request, render_template, redirect, session, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
import os
import redis
from utils import log_attempt, check_lockout, register_fail, reset_attempts

app = Flask(__name__, template_folder='../templates')
app.secret_key = 'supersecretkey'

# Configure rate limiter with fallback storage
try:
    redis_client = redis.Redis(host='localhost', port=6379, db=0)
    redis_client.ping()  # Test connection
    storage_uri = "redis://localhost:6379"
    print("Using Redis storage for rate limiting")
except redis.ConnectionError:
    storage_uri = "memory://"
    print("Redis not available, using in-memory storage (not for production)")

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=storage_uri,  # Only specify once
    default_limits=["5 per 15 minutes"]
)

# Load users with error handling
users = {}
try:
    if os.path.exists('users.json') and os.path.getsize('users.json') > 0:
        with open('users.json') as f:
            users = json.load(f)
    else:
        users = {"admin": "admin123"}
        with open('users.json', 'w') as f:
            json.dump(users, f)
except json.JSONDecodeError:
    users = {"admin": "admin123"}

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    ip = request.remote_addr
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if check_lockout(username):
            flash('Account is locked. Please try again later.', 'danger')
            log_attempt(ip, username, False, locked=True)
            return render_template('login.html')
    
        if username in users and users[username] == password:
            session['user'] = username
            reset_attempts(username)
            log_attempt(ip, username, True)
            return redirect('/dashboard')
        else:
            register_fail(username)
            log_attempt(ip, username, False)
            flash('Invalid credentials. Please try again.', 'danger')
            return render_template('login.html')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/')
    return render_template('dashboard.html', user=session['user'])

if __name__ == '__main__':
    app.run(debug=True)
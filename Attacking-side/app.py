from flask import Flask, request, render_template, redirect, session, flash
from flask_limiter import Limiter
from flask_limiter import get_remote_address
import json, time
from utils import log_attempt, check_locked, register_fail, reset_attempts

app = Flask(__name__)
app.secret_key = 'supersecretkey'
limiter = Limiter(get_remote_address, app=app, default_limits=["5 per 15 minutes"])

with open('users.json') as f:
    users = json.load(f)

# Rate limiting login route
app.route('/', methods=['GET', 'POST'])
@limiter.limit("5 per minute", key_func= get_remote_address)
def login():
    ip = request.remote_addr
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if check_locked(username):
            flash('Account is locked. Please try again later.', 'danger')
            log_attempt(ip, username, password, False, locked=True)
            return render_template('login.html')
    
        if username in users and users[username] == password:
            session['user'] = username
            reset_attempts(username)
            log_attempt(ip, username, password, True)
            return redirect('/success')
        else:
            register_fail(username)
            log_attempt(ip, username, password, False)
            flash('Invalid credentials. Please try again.', 'danger')
            return render_template('login.html')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return redirect('/')
    return render_template('dashboard.html', user=session['user'])

if __name__ == '__main__':
    app.run(debug=True)
    

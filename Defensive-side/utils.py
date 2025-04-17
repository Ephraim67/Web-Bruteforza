import csv
import os
import time
import json
from datetime import datetime

# Configuration
LOG_DIR = 'logs'
DATA_DIR = 'data'
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION = 300  # 5 minutes in seconds

# Ensure directories exist
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# File paths
LOG_FILE = os.path.join(LOG_DIR, 'login_attempts.log')
CSV_FILE = os.path.join(DATA_DIR, 'login_attempts.csv')
TRACKER_FILE = os.path.join(DATA_DIR, 'fail_tracker.json')

# Initialize fail tracker
try:
    with open(TRACKER_FILE, 'r') as f:
        fail_tracker = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    fail_tracker = {}

def save_tracker():
    """Save the fail tracker to disk"""
    with open(TRACKER_FILE, 'w') as f:
        json.dump(fail_tracker, f)

def log_attempt(ip, username, success, locked=False):
    """Log login attempts to both log file and CSV"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    status = 'Success' if success else 'Failure'
    
    # Write to log file
    with open(LOG_FILE, 'a') as f:
        f.write(f"{timestamp}, {ip}, {username}, {status}, Locked: {locked}\n")
    
    # Write to CSV
    with open(CSV_FILE, 'a', newline='') as csvf:
        writer = csv.writer(csvf)
        writer.writerow([timestamp, ip, username, success, locked])

def register_fail(username):
    """Register a failed login attempt and persist to disk"""
    if username not in fail_tracker:
        fail_tracker[username] = {
            'count': 0,
            'last_fail': time.time()
        }
    
    fail_tracker[username]['count'] += 1
    fail_tracker[username]['last_fail'] = time.time()
    save_tracker()

def check_lockout(username):
    """Check if account is locked out"""
    if username in fail_tracker:
        info = fail_tracker[username]
        if (info['count'] >= LOCKOUT_THRESHOLD and 
            (time.time() - info['last_fail']) < LOCKOUT_DURATION):
            return True
    return False

def reset_attempts(username):
    """Reset failed attempts counter for a username"""
    if username in fail_tracker:
        del fail_tracker[username]
        save_tracker()

def cleanup_expired_lockouts():
    """Clean up expired lockouts (call periodically)"""
    current_time = time.time()
    expired_users = [
        username for username, info in fail_tracker.items()
        if info['count'] >= LOCKOUT_THRESHOLD and
        (current_time - info['last_fail']) >= LOCKOUT_DURATION
    ]
    for username in expired_users:
        del fail_tracker[username]
    if expired_users:
        save_tracker()
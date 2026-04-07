from flask import Flask, render_template, request, redirect, url_for, flash, get_flashed_messages, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
from dotenv import load_dotenv
import hashlib
import json
import sqlite3
import os
from time import time
from blockchain_voting_system import Blockchain

# --- 1. CONFIGURATION & SECURITY ---
# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Load Secret Key from .env (Safety fallback provided for dev)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'dev_fallback_key_do_not_use_in_prod')

# Auto-Logout after 5 minutes of inactivity
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 

DB_NAME = "users.db"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CHAIN_FILE = os.path.join(BASE_DIR, 'blockchain.json')

def init_db():
    """Creates the User table if it doesn't exist"""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()

init_db() # Run once on startup

# Create admin user if not exists
with sqlite3.connect(DB_NAME) as conn:
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        hashed_pw = generate_password_hash('admin123', method='scrypt')
        cursor.execute("INSERT INTO users (username, password) VALUES ('admin', ?)", (hashed_pw,))
        conn.commit()

ACTIVITY_LOG_FILE = os.path.join(BASE_DIR, 'activity_log.json')

def log_activity(action, user, details=""):
    """Log user activities for audit trail"""
    try:
        with open(ACTIVITY_LOG_FILE, 'r') as f:
            logs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []
    
    logs.append({
        'timestamp': time(),
        'action': action,
        'user': user,
        'details': details
    })
    
    with open(ACTIVITY_LOG_FILE, 'w') as f:
        json.dump(logs, f, indent=4)

def get_recent_activities(limit=10, redact=False):
    """Get recent activities for display, redacting private details for non-admin users."""
    try:
        with open(ACTIVITY_LOG_FILE, 'r') as f:
            logs = json.load(f)
        processed = []
        for log in logs:
            entry = {
                'timestamp': log.get('timestamp', time()),
                'timestamp_formatted': datetime.fromtimestamp(log.get('timestamp', time())).strftime('%H:%M:%S'),
                'action': log.get('action', 'Activity'),
                'user': log.get('user', 'System'),
                'details': log.get('details', '')
            }
            if redact:
                entry['user'] = 'Anonymous'
                if entry['action'] == 'Vote cast':
                    entry['details'] = 'A vote was submitted.'
                elif entry['action'] in ['User logged in', 'User logged out', 'User registered']:
                    entry['details'] = ''
                elif entry['action'] in ['Block mined', 'Chain validation passed', 'Chain validation failed']:
                    entry['details'] = 'A system operation was recorded.'
                else:
                    entry['details'] = entry['details'] or 'System activity recorded.'
            processed.append(entry)
        return processed[-limit:][::-1]  # Last 10, reversed (newest first)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def build_vote_history():
    """Build detailed vote history for admin review."""
    history = []
    for block in blockchain.chain:
        for vote in block.get('votes', []):
            history.append({
                'voter_id': vote.get('voter_id'),
                'candidate': vote.get('candidate'),
                'block_index': block.get('index'),
                'status': 'Mined',
                'timestamp': datetime.fromtimestamp(vote.get('timestamp', time())).strftime('%Y-%m-%d %H:%M:%S')
            })
    for vote in blockchain.pending_votes:
        history.append({
            'voter_id': vote.get('voter_id'),
            'candidate': vote.get('candidate'),
            'block_index': 'Pending',
            'status': 'Pending',
            'timestamp': datetime.fromtimestamp(vote.get('timestamp', time())).strftime('%Y-%m-%d %H:%M:%S')
        })
    return sorted(history, key=lambda x: x['timestamp'], reverse=True)
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user_data = cursor.fetchone()
        if user_data:
            return User(id=user_data[0], username=user_data[1], password=user_data[2])
    return None

def load_candidates(filename='names.txt'):
    base = os.path.dirname(__file__)
    path = os.path.join(base, filename)
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        return ["Candidate A", "Candidate B"]

CANDIDATES = load_candidates()
blockchain = Blockchain.load_state(CHAIN_FILE)

# --- 4. ROUTES ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                flash("Username already taken.", "danger")
            else:
                # Hash password before saving
                hashed_pw = generate_password_hash(password, method='scrypt')
                cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
                conn.commit()
                log_activity("User registered", username)
                flash("Account created! Please login.", "success")
                return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user_data = cursor.fetchone()
            
            if user_data and check_password_hash(user_data[2], password):
                user_obj = User(id=user_data[0], username=user_data[1], password=user_data[2])
                login_user(user_obj)
                
                # Activate 5-minute timer
                session.permanent = True
                
                log_activity("User logged in", username)
                flash(f"Welcome back, {username}!", "success")
                return redirect(url_for('index'))
            else:
                flash("Invalid username or password.", "danger")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    vote_counts = blockchain.tally_votes(CANDIDATES)
    redact = current_user.username != 'admin'
    activities = get_recent_activities(redact=redact)
    return render_template('index.html', 
                           chain=blockchain.chain, 
                           pending=blockchain.pending_votes,
                           candidates=CANDIDATES,
                           vote_counts=vote_counts,
                           chain_valid=blockchain.is_chain_valid(blockchain.chain),
                           user=current_user,
                           activities=activities)

@app.route('/vote', methods=['POST'])
@login_required
def vote():
    voter_id = current_user.username
    candidate = request.form.get('candidate')
    
    if candidate:
        success = blockchain.new_vote(voter_id, candidate)
        if success:
            blockchain.save_state(CHAIN_FILE)
            log_activity("Vote cast", current_user.username, f"For {candidate}")
            flash(f"Vote cast for {candidate} successfully!", "success")
        else:
            flash(f"ERROR: {voter_id}, you have already voted!", "danger")
    else:
        flash("Error: Missing Candidate selection.", "warning")
            
    return redirect(url_for('index'))

@app.route('/mine', methods=['GET'])
@login_required
def mine():
    if not blockchain.pending_votes:
        flash("No votes to mine.", "warning")
        return redirect(url_for('index'))

    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block['proof'])
    previous_hash = blockchain.hash(last_block)
    blockchain.new_block(proof, previous_hash)
    blockchain.save_state(CHAIN_FILE)
    
    log_activity("Block mined", current_user.username)
    flash("Block mined successfully! Votes are now immutable.", "success")
    return redirect(url_for('index'))

@app.route('/about', methods=['GET'])
def about():
    return render_template('about.html')

@app.route('/validate', methods=['GET'])
def validate():
    if blockchain.is_chain_valid(blockchain.chain):
        log_activity("Chain validation passed", current_user.username)
        flash("System Secure: Blockchain integrity verified.", "success")
    else:
        log_activity("Chain validation failed", current_user.username)
        flash("SECURITY ALERT: Blockchain has been tampered with!", "danger")
    return redirect(url_for('index'))

@app.route('/chart-data')
@login_required
def chart_data():
    vote_counts = blockchain.tally_votes(CANDIDATES)
    data = {
        'labels': list(vote_counts.keys()),
        'datasets': [{
            'label': 'Votes',
            'data': list(vote_counts.values()),
            'backgroundColor': [
                'rgba(255, 99, 132, 0.8)',
                'rgba(54, 162, 235, 0.8)',
                'rgba(255, 205, 86, 0.8)',
                'rgba(75, 192, 192, 0.8)',
                'rgba(153, 102, 255, 0.8)'
            ],
            'borderColor': [
                'rgba(255, 99, 132, 1)',
                'rgba(54, 162, 235, 1)',
                'rgba(255, 205, 86, 1)',
                'rgba(75, 192, 192, 1)',
                'rgba(153, 102, 255, 1)'
            ],
            'borderWidth': 1
        }]
    }
    return jsonify(data)

@app.route('/admin')
@login_required
def admin():
    if current_user.username != 'admin':  # Simple admin check
        flash("Access denied.", "danger")
        return redirect(url_for('index'))
    vote_counts = blockchain.tally_votes(CANDIDATES)
    total_votes = sum(vote_counts.values())
    total_blocks = len(blockchain.chain)
    pending_votes = len(blockchain.pending_votes)
    vote_history = build_vote_history()
    return render_template('admin.html', 
                           vote_counts=vote_counts, 
                           total_votes=total_votes,
                           total_blocks=total_blocks,
                           pending_votes=pending_votes,
                           chain_valid=blockchain.is_chain_valid(blockchain.chain),
                           vote_history=vote_history)

@app.route('/audit')
@login_required
def audit():
    tampered_blocks = []
    for i, block in enumerate(blockchain.chain):
        if i > 0:
            if block['previous_hash'] != blockchain.hash(blockchain.chain[i-1]):
                tampered_blocks.append(i)
    return render_template('audit.html', tampered_blocks=tampered_blocks, chain=blockchain.chain)

@app.route('/overview')
def overview():
    return render_template('overview.html')
@app.errorhandler(404)
def not_found(error):
    return "Page not found", 404

@app.errorhandler(500)
def internal_error(error):
    return "Internal server error", 500

if __name__ == '__main__':
    app.run(debug=False, port=5000)
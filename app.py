import uuid
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ssl
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

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.getenv('TMPDIR') or os.getenv('TEMP') or os.getenv('TMP') or '/tmp'
if not os.path.isabs(DATA_DIR):
    DATA_DIR = os.path.join(BASE_DIR, DATA_DIR)

DB_NAME = os.path.join(DATA_DIR, 'users.db')
CHAIN_FILE = os.path.join(DATA_DIR, 'blockchain.json')
_db_initialized = False


def ensure_db():
    """Lazy initialization of database. Only creates tables if needed."""
    global _db_initialized
    if _db_initialized:
        return
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    email TEXT UNIQUE,
                    is_verified INTEGER DEFAULT 0,
                    verification_token TEXT
                )
            ''')
            
            # Auto-migrate existing databases to include new columns
            try:
                cursor.execute("ALTER TABLE users ADD COLUMN email TEXT UNIQUE")
                cursor.execute("ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 0")
                cursor.execute("ALTER TABLE users ADD COLUMN verification_token TEXT")
            except sqlite3.OperationalError:
                pass # Columns already exist
                
            conn.commit()
        
        # Create admin user if not exists
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = 'admin'")
            if not cursor.fetchone():
                hashed_pw = generate_password_hash('admin123', method='scrypt')
                cursor.execute("INSERT INTO users (username, password, email, is_verified) VALUES ('admin', ?, 'admin@tat.node', 1)", (hashed_pw,))
                conn.commit()
        
        _db_initialized = True
    except Exception as e:
        print(f"Warning: DB initialization deferred ({type(e).__name__}), will retry on next request")

# Initialize database on startup, but don't crash if it fails
ensure_db()

def send_verification_email(recipient_email, verify_link):
    """Sends a real verification email using SMTP."""
    sender_email = os.getenv('MAIL_USERNAME')
    sender_password = os.getenv('MAIL_PASSWORD')
    
    if not sender_email or not sender_password:
        print("ERROR: Mail credentials not found in .env")
        return False

    message = MIMEMultipart("alternative")
    message["Subject"] = "Verify your TAT Node Identity"
    message["From"] = sender_email
    message["To"] = recipient_email

    # Plain text version
    text = f"Welcome to TAT Node!\n\nPlease verify your account by clicking the following link:\n{verify_link}"
    
    # HTML version for better formatting
    html = f"""\
    <html>
      <body style="font-family: Arial, sans-serif; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
            <h2 style="color: #090979;">Welcome to TAT Node!</h2>
            <p>Your blockchain identity has been reserved. To complete your registration and enter the polling station, please verify your email address.</p>
            <div style="text-align: center; margin: 30px 0;">
                <a href="{verify_link}" style="background-color: #38ef7d; color: white; padding: 12px 25px; text-decoration: none; border-radius: 50px; font-weight: bold;">Verify My Account</a>
            </div>
            <p style="font-size: 0.8em; color: #777;">If the button doesn't work, copy and paste this link into your browser:<br>{verify_link}</p>
        </div>
      </body>
    </html>
    """

    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")
    message.attach(part1)
    message.attach(part2)

    try:
        # Using Port 587 (TLS) instead of 465 (SSL)
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.ehlo()
        server.starttls() # This line secures the connection
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, message.as_string())
        server.quit()
        return True
    except Exception as e:
        # This will print the EXACT reason it failed in your terminal
        print(f"\n" + "!"*50)
        print(f"EMAIL FAILED TO SEND. ERROR DETAILS:")
        print(f"{e}")
        print("!"*50 + "\n")
        return False

ACTIVITY_LOG_FILE = os.path.join(DATA_DIR, 'activity_log.json')

def log_activity(action, user, details=""):
    """Log user activities for audit trail"""
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
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
    except Exception as e:
        print(f"Warning: Activity log failed ({type(e).__name__}: {e}), continuing anyway")

def get_recent_activities(limit=10, redact=False):
    """Get recent activities for display, redacting private details for non-admin users."""
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        try:
            with open(ACTIVITY_LOG_FILE, 'r') as f:
                logs = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []
        
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
    except Exception as e:
        print(f"Error in get_recent_activities: {type(e).__name__}: {e}")
        return []


def build_vote_history():
    """Build detailed vote history for admin review."""
    try:
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
    except Exception as e:
        print(f"Error in build_vote_history: {type(e).__name__}: {e}")
        return []
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

def validate_voter_id(voter_id):
    """Validate voter ID format silently, with an exception for the admin."""
    # 1. Allow the admin to bypass the numeric check
    if voter_id == 'admin':
        return True, ""
        
    # 2. Check if normal voters are using a number between 1 and 50000
    try:
        id_int = int(voter_id)
        if id_int < 1 or id_int > 50000:
            return False, "Invalid Voter ID."
        return True, ""
    except ValueError:
        return False, "Invalid Voter ID."
    
CANDIDATES = load_candidates()
try:
    blockchain = Blockchain.load_state(CHAIN_FILE)
except Exception as e:
    print(f"Warning: Could not load blockchain state ({type(e).__name__}), starting fresh")
    blockchain = Blockchain()

# --- 3. REQUEST HOOKS ---
@app.before_request
def before_request():
    """Ensure database is initialized before each request"""
    ensure_db()

# --- 4. ROUTES ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        
        # Validate voter ID format silently
        is_valid, error_msg = validate_voter_id(username)
        if not is_valid:
            flash(f"Registration failed: {error_msg}", "danger")
            return render_template('register.html')
        
        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
                if cursor.fetchone():
                    flash("Voter ID or Email is already registered.", "danger")
                else:
                    hashed_pw = generate_password_hash(password, method='scrypt')
                    token = str(uuid.uuid4())
                    
                    cursor.execute("INSERT INTO users (username, password, email, is_verified, verification_token) VALUES (?, ?, ?, 0, ?)", 
                                   (username, hashed_pw, email, token))
                    conn.commit()
                    log_activity("User registered", username)
                    
                    # --- SEND REAL EMAIL ---
                    verify_link = url_for('verify_email', token=token, _external=True)
                    email_sent = send_verification_email(email, verify_link)
                    
                    if email_sent:
                        flash("Account created! Please check your email inbox to verify your identity.", "success")
                    else:
                        flash("Account created, but we couldn't send the verification email. Please contact support.", "warning")
                        
                    return redirect(url_for('login'))
        except Exception as e:
            print(f"Error in register: {type(e).__name__}: {e}")
            flash("Registration service temporarily unavailable. Please try again.", "danger")
    return render_template('register.html')

@app.route('/verify/<token>')
def verify_email(token):
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE verification_token = ?", (token,))
            user = cursor.fetchone()
            
            if user:
                # Mark as verified and clear the token
                cursor.execute("UPDATE users SET is_verified = 1, verification_token = NULL WHERE id = ?", (user[0],))
                conn.commit()
                flash("Identity verified successfully! You can now enter the polling station.", "success")
            else:
                flash("Invalid or expired verification link.", "danger")
    except Exception as e:
        print(f"Error in verify: {type(e).__name__}: {e}")
        flash("Verification service unavailable.", "danger")
        
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        is_valid, error_msg = validate_voter_id(username)
        if not is_valid:
            flash(f"Login failed: {error_msg}", "danger")
            return render_template('login.html')
        
        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                # Fetch id, username, password, and is_verified status
                cursor.execute("SELECT id, username, password, is_verified FROM users WHERE username = ?", (username,))
                user_data = cursor.fetchone()
                
                if user_data and check_password_hash(user_data[2], password):
                    
                    # Prevent login if email is not verified
                    if user_data[3] == 0: 
                        flash("Access Denied: Please verify your email address before logging in.", "warning")
                        return render_template('login.html')

                    user_obj = User(id=user_data[0], username=user_data[1], password=user_data[2])
                    login_user(user_obj)
                    
                    session.permanent = True
                    log_activity("User logged in", username)
                    flash(f"Welcome back, {username}!", "success")
                    return redirect(url_for('index'))
                else:
                    flash("Invalid credentials.", "danger")
        except Exception as e:
            print(f"Error in login: {type(e).__name__}: {e}")
            flash("Login service temporarily unavailable. Please try again.", "danger")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    try:
        logout_user()
        flash("You have been logged out.", "info")
    except Exception as e:
        print(f"Error in logout: {type(e).__name__}: {e}")
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    try:
        vote_counts = blockchain.tally_votes(CANDIDATES)
        chain_valid = blockchain.is_chain_valid(blockchain.chain)
    except Exception as e:
        print(f"Error in index: {type(e).__name__}: {e}")
        vote_counts = {c: 0 for c in CANDIDATES}
        chain_valid = False
    
    return render_template('index.html', 
                           chain=blockchain.chain, 
                           pending=blockchain.pending_votes,
                           candidates=CANDIDATES,
                           vote_counts=vote_counts,
                           chain_valid=chain_valid,
                           user=current_user)

@app.route('/vote', methods=['POST'])
@login_required
def vote():
    voter_id = current_user.username
    candidate = request.form.get('candidate')
    
    # Admin check: Admins cannot vote
    if current_user.username == 'admin':
        flash("Administrators are not permitted to vote in this system.", "warning")
        return redirect(url_for('index'))
    
 # Validate voter ID format silently
    try:
        voter_id_int = int(voter_id)
        if voter_id_int < 1 or voter_id_int > 50000:
            flash("Invalid Voter Identity.", "danger")
            return redirect(url_for('index'))
    except ValueError:
        flash("Invalid Voter Identity.", "danger")
        return redirect(url_for('index'))
       
    if candidate:
        try:
            success = blockchain.new_vote(voter_id, candidate)
            if success:
                try:
                    blockchain.save_state(CHAIN_FILE)
                except Exception as e:
                    print(f"Warning: Could not save blockchain state ({type(e).__name__}), continuing")
                log_activity("Vote cast", current_user.username, f"For {candidate}")
                flash(f"Vote cast for {candidate} successfully!", "success")
            else:
                flash(f"ERROR: {voter_id}, you have already voted!", "danger")
        except Exception as e:
            print(f"Error in vote: {type(e).__name__}: {e}")
            flash("Error processing vote. Please try again.", "danger")
    else:
        flash("Error: Missing Candidate selection.", "warning")
            
    return redirect(url_for('index'))

@app.route('/mine', methods=['GET'])
@login_required
def mine():
    if not blockchain.pending_votes:
        flash("No votes to mine.", "warning")
        return redirect(url_for('index'))

    try:
        last_block = blockchain.last_block
        proof = blockchain.proof_of_work(last_block['proof'])
        previous_hash = blockchain.hash(last_block)
        blockchain.new_block(proof, previous_hash)
        try:
            blockchain.save_state(CHAIN_FILE)
        except Exception as e:
            print(f"Warning: Could not save blockchain state ({type(e).__name__}), continuing")
        
        log_activity("Block mined", current_user.username)
        flash("Block mined successfully! Votes are now immutable.", "success")
    except Exception as e:
        print(f"Error in mine: {type(e).__name__}: {e}")
        flash("Error mining block. Please try again.", "danger")
    return redirect(url_for('index'))

@app.route('/about', methods=['GET'])
def about():
    return render_template('about.html')

@app.route('/validate', methods=['GET'])
@login_required
def validate():
    try:
        if blockchain.is_chain_valid(blockchain.chain):
            log_activity("Chain validation passed", current_user.username)
            flash("System Secure: Blockchain integrity verified.", "success")
        else:
            log_activity("Chain validation failed", current_user.username)
            flash("SECURITY ALERT: Blockchain has been tampered with!", "danger")
    except Exception as e:
        print(f"Error in validate: {type(e).__name__}: {e}")
        flash("Validation service temporarily unavailable.", "warning")
    return redirect(url_for('index'))

@app.route('/chart-data')
@login_required
def chart_data():
    try:
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
    except Exception as e:
        print(f"Error in chart-data: {type(e).__name__}: {e}")
        return jsonify({'error': 'Failed to load chart data'}), 500

@app.route('/admin')
@login_required
def admin():
    if current_user.username != 'admin':  # Simple admin check
        flash("Access denied.", "danger")
        return redirect(url_for('index'))
    try:
        vote_counts = blockchain.tally_votes(CANDIDATES)
        total_votes = sum(vote_counts.values())
        total_blocks = len(blockchain.chain)
        pending_votes = len(blockchain.pending_votes)
        vote_history = build_vote_history()
        activities = get_recent_activities(redact=False)
        chain_valid = blockchain.is_chain_valid(blockchain.chain)
    except Exception as e:
        print(f"Error in admin: {type(e).__name__}: {e}")
        vote_counts = {c: 0 for c in CANDIDATES}
        total_votes = 0
        total_blocks = 0
        pending_votes = 0
        vote_history = []
        activities = []
        chain_valid = False
    
    return render_template('admin.html', 
                           vote_counts=vote_counts, 
                           total_votes=total_votes,
                           total_blocks=total_blocks,
                           pending_votes=pending_votes,
                           chain_valid=chain_valid,
                           vote_history=vote_history,
                           activities=activities)

@app.route('/audit')
@login_required
def audit():
    try:
        tampered_blocks = []
        for i, block in enumerate(blockchain.chain):
            if i > 0:
                if block['previous_hash'] != blockchain.hash(blockchain.chain[i-1]):
                    tampered_blocks.append(i)
    except Exception as e:
        print(f"Error in audit: {type(e).__name__}: {e}")
        tampered_blocks = []
    return render_template('audit.html', tampered_blocks=tampered_blocks, chain=blockchain.chain)

@app.route('/overview')
def overview():
    return render_template('overview.html')
@app.errorhandler(404)
def not_found(error):
    return "Page not found", 404

@app.errorhandler(500)
def internal_error(error):
    import traceback
    print(f"500 Error: {error}")
    traceback.print_exc()
    return "Internal server error", 500

if __name__ == '__main__':
    app.run(debug=False, port=5000)
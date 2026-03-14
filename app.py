from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
from flask_mail import Mail, Message
from pymongo import MongoClient
from bson.objectid import ObjectId
from werkzeug.utils import secure_filename
from functools import wraps
import bcrypt
import os
import random
import string
import uuid
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, redirect, url_for
from multi_tab_session import MultiTabSession
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()



# ===============================
# MULTI TAB SESSION STORAGE
# ===============================

MULTI_TAB_SESSIONS = {}


def create_tab_session(user_data):
    tab_id = str(uuid.uuid4())
    MULTI_TAB_SESSIONS[tab_id] = user_data
    return tab_id


def get_tab_session():
    tab_id = request.headers.get("X-Tab-ID")
    if not tab_id:
        return None
    return MULTI_TAB_SESSIONS.get(tab_id)


def destroy_tab_session():
    tab_id = request.headers.get("X-Tab-ID")
    if tab_id and tab_id in MULTI_TAB_SESSIONS:
        del MULTI_TAB_SESSIONS[tab_id]



# Global instance
multi_tab_session = MultiTabSession()

def get_current_tab_data():
    session_id = multi_tab_session.get_session_id()
    return multi_tab_session.get_user_data(session_id)

# Session structure for multiple roles
# session['users'] = {
#     'role1': {'user_id': '...', 'username': '...', 'email': '...'},
#     'role2': {'user_id': '...', 'username': '...', 'email': '...'}
# }
# session['active_role'] = 'role1'

def get_current_active_role():
    tab_data = get_current_tab_data()
    if tab_data:
        return tab_data.get('active_role')
    return None



app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
app.permanent_session_lifetime = timedelta(hours=1)

# MongoDB Configuration
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
client = MongoClient(MONGO_URI)
db = client['inventory_management']

# Collections
users_collection = db['users']
products_collection = db['products']
categories_collection = db['categories']
orders_collection = db['orders']
manager_orders_collection = db['manager_orders']
requests_collection = db['requests']
notices_collection = db['notices']
cart_collection = db['cart']
payment_settings_collection = db['payment_settings']
payments_collection = db['payments']

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', '')
mail = Mail(app)

# File Upload Configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Decorators for role-based access
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        tab_data = get_current_tab_data()

        if not tab_data or not tab_data.get('active_role'):
            return redirect(url_for('login'))

        request.user = tab_data
        return f(*args, **kwargs)

    return decorated_function


def role_required(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            tab_data = get_current_tab_data()

            if not tab_data or not tab_data.get('active_role'):
                return redirect(url_for('login'))

            if tab_data.get("active_role") not in roles:
                return redirect(url_for('dashboard'))

            request.user = tab_data
            return f(*args, **kwargs)

        return decorated_function
    return wrapper


# OTP Collection for better management
otp_collection = db['otps']

# Helper Functions
def generate_otp(length=6):
    """Generate a random OTP of specified length"""
    return ''.join(random.choices(string.digits, k=length))

def send_otp_email(email, otp, purpose='verification'):
    """Send OTP via email"""
    try:
        purpose_messages = {
            'verification': {
                'subject': 'Email Verification OTP',
                'body': f'Your email verification OTP is: {otp}\nThis OTP will expire in 10 minutes.\n\nIf you did not request this, please ignore this email.'
            },
            'password_reset': {
                'subject': 'Password Reset OTP',
                'body': f'Your password reset OTP is: {otp}\nThis OTP will expire in 10 minutes.\n\nIf you did not request this, please ignore this email.'
            },
            'login_2fa': {
                'subject': 'Login Verification OTP',
                'body': f'Your login verification OTP is: {otp}\nThis OTP will expire in 5 minutes.\n\nIf you did not attempt to login, please secure your account immediately.'
            }
        }
        
        msg_data = purpose_messages.get(purpose, purpose_messages['verification'])
        msg = Message(msg_data['subject'], recipients=[email])
        msg.body = msg_data['body']
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def store_otp(email, otp, purpose='verification', expiry_minutes=10):
    """Store OTP in database with expiry"""
    expiry = datetime.utcnow() + timedelta(minutes=expiry_minutes)
    
    # Remove old OTPs for this email and purpose
    otp_collection.delete_many({
        'email': email,
        'purpose': purpose,
        'used': False
    })
    
    # Store new OTP
    otp_collection.insert_one({
        'email': email,
        'otp': otp,
        'purpose': purpose,
        'expiry': expiry,
        'used': False,
        'attempts': 0,
        'created_at': datetime.utcnow()
    })
    
    # Also store in user collection for backward compatibility
    user = users_collection.find_one({'email': email})
    if user:
        if purpose == 'password_reset':
            users_collection.update_one(
                {'_id': user['_id']},
                {'$set': {'reset_otp': otp, 'otp_expiry': expiry}}
            )
        elif purpose == 'verification':
            users_collection.update_one(
                {'_id': user['_id']},
                {'$set': {'verification_otp': otp, 'verification_otp_expiry': expiry}}
            )

def verify_otp(email, otp, purpose='verification'):
    """Verify OTP"""
    # Check in OTP collection first
    otp_record = otp_collection.find_one({
        'email': email,
        'purpose': purpose,
        'used': False
    })
    
    if not otp_record:
        # Fallback to user collection for backward compatibility
        user = users_collection.find_one({'email': email})
        if not user:
            return False, 'User not found'
        
        if purpose == 'password_reset':
            stored_otp = user.get('reset_otp')
            expiry = user.get('otp_expiry')
        elif purpose == 'verification':
            stored_otp = user.get('verification_otp')
            expiry = user.get('verification_otp_expiry')
        else:
            return False, 'Invalid purpose'
        
        if not stored_otp or stored_otp != otp:
            return False, 'Invalid OTP'
        
        if expiry and expiry < datetime.utcnow():
            return False, 'OTP has expired'
        
        return True, 'OTP verified'
    
    # Check expiry
    if otp_record['expiry'] < datetime.utcnow():
        otp_collection.update_one(
            {'_id': otp_record['_id']},
            {'$set': {'used': True}}
        )
        return False, 'OTP has expired'
    
    # Check attempts (max 5 attempts)
    if otp_record.get('attempts', 0) >= 5:
        otp_collection.update_one(
            {'_id': otp_record['_id']},
            {'$set': {'used': True}}
        )
        return False, 'Too many failed attempts. OTP has been disabled.'
    
    # Verify OTP
    if otp_record['otp'] != otp:
        otp_collection.update_one(
            {'_id': otp_record['_id']},
            {'$inc': {'attempts': 1}}
        )
        return False, 'Invalid OTP'
    
    # Mark as used
    otp_collection.update_one(
        {'_id': otp_record['_id']},
        {'$set': {'used': True, 'verified_at': datetime.utcnow()}}
    )
    
    return True, 'OTP verified'

def can_resend_otp(email, purpose='verification', cooldown_minutes=1):
    """Check if OTP can be resent (cooldown period)"""
    recent_otp = otp_collection.find_one({
        'email': email,
        'purpose': purpose
    }, sort=[('created_at', -1)])
    
    if not recent_otp:
        return True
    
    time_since_last = datetime.utcnow() - recent_otp['created_at']
    return time_since_last.total_seconds() >= (cooldown_minutes * 60)

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def safe_objectid_compare(id1, id2):
    """Safely compare two IDs that might be ObjectId or string"""
    if id1 is None or id2 is None:
        return id1 == id2
    # Convert both to strings for comparison
    str1 = str(id1) if id1 else None
    str2 = str(id2) if id2 else None
    return str1 == str2

def safe_objectid(id_value):
    """Safely convert a value to ObjectId, returns None if invalid"""
    if not id_value:
        return None
    try:
        return ObjectId(id_value)
    except:
        return None

# Context Processor for Templates
@app.context_processor
def inject_roles():
    active_role = get_current_active_role()
    return {
        'current_roles': session.get('users', {}),
        'active_role': active_role,
        'current_endpoint': request.endpoint
    }

# Routes
@app.route('/')
def index():
    response = make_response(render_template('auth/login.html'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = users_collection.find_one({'email': email})



        if user and check_password(password, user["password"]):
            # Check if 2FA is enabled
            if user.get('two_factor_enabled', False):
                # Store login info in session temporarily
                session['pending_login'] = {
                    'user_id': str(user['_id']),
                    'username': user['username'],
                    'email': user['email'],
                    'role': user['role']
                }
                
                # Send 2FA OTP
                otp = generate_otp(6)
                store_otp(email, otp, 'login_2fa', expiry_minutes=5)
                
                if send_otp_email(email, otp, 'login_2fa'):
                    flash('Please verify your login with the OTP sent to your email.', 'info')
                    return redirect(url_for('verify_otp', email=email, purpose='login_2fa'))
                else:
                    flash('Error sending 2FA code. Please try again.', 'danger')
                    session.pop('pending_login', None)
                    return redirect(url_for('login'))
            else:
                # Regular login without 2FA
                session.permanent = False

                # Initialize users dict if not exists
                if 'users' not in session:
                    session['users'] = {}

                # Add this user to the session (allow multiple roles)
                role = user['role']
                session['users'][role] = {
                    'user_id': str(user['_id']),
                    'username': user['username'],
                    'email': user['email'],
                    'role': role
                }

                # Set active role to this user for this tab
                session['active_role'] = role
                session_id = multi_tab_session.get_session_id()
                multi_tab_session.set_user_data(session_id, {
                    'user_id': str(user['_id']),
                    'active_role': role
                })

                flash('Login successful!', 'success')
                response = make_response(redirect(url_for('dashboard')))
                response.set_cookie('multi_tab_session_id', session_id, httponly=True, secure=False)  # secure=False for development
                return response
        else:
            flash('Invalid email or password.', 'danger')
    
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role', 'staff')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))
        
        if users_collection.find_one({'email': email}):
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))
        
        user_data = {
            'username': username,
            'email': email,
            'password': hash_password(password),
            'role': role,
            'created_at': datetime.utcnow(),
            'is_active': True
        }
        
        # Add role-specific fields
        if role == 'supplier':
            user_data['company_name'] = request.form.get('company_name', '')
            user_data['contact_number'] = request.form.get('contact_number', '')
            user_data['address'] = request.form.get('address', '')
        elif role == 'staff':
            user_data['manager_id'] = request.form.get('manager_id', None)
        
        users_collection.insert_one(user_data)
        
        # Send email verification OTP
        otp = generate_otp(6)
        store_otp(email, otp, 'verification', expiry_minutes=10)
        
        if send_otp_email(email, otp, 'verification'):
            flash('Registration successful! Please verify your email with the OTP sent to your inbox.', 'success')
            return redirect(url_for('verify_otp', email=email, purpose='verification'))
        else:
            flash('Registration successful! However, we could not send verification email. Please contact support.', 'warning')
            return redirect(url_for('login'))
    
    managers = list(users_collection.find({'role': 'manager'}))
    return render_template('auth/register.html', managers=managers)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = users_collection.find_one({'email': email})

        if user:
            # Ensure default admin user always has admin role
            if user.get('email') == 'admin@example.com' and user.get('username') == 'admin' and user.get('role') != 'admin':
                users_collection.update_one({'_id': user['_id']}, {'$set': {'role': 'admin'}})
                user['role'] = 'admin'
            # Check cooldown period
            if not can_resend_otp(email, 'password_reset', cooldown_minutes=1):
                flash('Please wait before requesting a new OTP.', 'warning')
                return redirect(url_for('forgot_password'))
            
            otp = generate_otp(6)
            store_otp(email, otp, 'password_reset', expiry_minutes=10)
            
            if send_otp_email(email, otp, 'password_reset'):
                flash('OTP sent to your email.', 'success')
                return redirect(url_for('verify_otp', email=email, purpose='password_reset'))
            else:
                flash('Error sending email. Please try again.', 'danger')
        else:
            flash('Email not found.', 'danger')
    
    return render_template('auth/forgot_password.html')

@app.route('/verify-otp/<email>', methods=['GET', 'POST'])
@app.route('/verify-otp/<email>/<purpose>', methods=['GET', 'POST'])
def verify_otp(email, purpose='password_reset'):
    # Handle enable 2FA verification
    if purpose == 'verification' and session.get('enable_2fa_pending'):
        if request.method == 'POST':
            otp = request.form.get('otp', '')
            otp = str(otp).strip()

            if not otp or len(otp) != 6:
                flash('Please enter a valid 6-digit OTP.', 'danger')
                return render_template('auth/verify_otp.html', email=email, purpose=purpose)
            
            is_valid, message = verify_otp(email, otp, purpose)
            
            if is_valid:
                # Enable 2FA
                user = users_collection.find_one({'email': email})
                if user:
                    users_collection.update_one(
                        {'_id': user['_id']},
                        {'$set': {'two_factor_enabled': True, 'email_verified': True}}
                    )
                    session.pop('enable_2fa_pending', None)
                    flash('Two-Factor Authentication enabled successfully!', 'success')
                    return redirect(url_for('profile'))
            else:
                flash(message, 'danger')
        
        return render_template('auth/verify_otp.html', email=email, purpose=purpose)
    if request.method == 'POST':
        otp = request.form.get('otp', '')
        otp = str(otp).strip()

        if not otp or len(otp) != 6:
            flash('Please enter a valid 6-digit OTP.', 'danger')
            return render_template('auth/verify_otp.html', email=email, purpose=purpose)
        
        is_valid, message = verify_otp(email, otp, purpose)
        
        if is_valid:
            if purpose == 'password_reset':
                session['reset_email'] = email
                flash('OTP verified successfully!', 'success')
                return redirect(url_for('reset_password'))
            elif purpose == 'verification':
                # Mark email as verified
                user = users_collection.find_one({'email': email})
                if user:
                    users_collection.update_one(
                        {'_id': user['_id']},
                        {'$set': {'email_verified': True, 'email_verified_at': datetime.utcnow()}}
                    )
                flash('Email verified successfully!', 'success')
                return redirect(url_for('login'))
            elif purpose == 'login_2fa':
                # Complete the login process
                if 'pending_login' in session:
                    login_data = session.pop('pending_login')

                    # Initialize users dict if not exists
                    if 'users' not in session:
                        session['users'] = {}

                    # Add this user to the session
                    role = login_data['role']
                    session['users'][role] = {
                        'user_id': login_data['user_id'],
                        'username': login_data['username'],
                        'email': login_data['email'],
                        'role': role
                    }

                    # Set active role to this user
                    session['active_role'] = role
                    session['role'] = role
                    session['2fa_verified'] = True

                    # Set user data in multi-tab session
                    session_id = multi_tab_session.get_session_id()
                    multi_tab_session.set_user_data(session_id, {
                        'user_id': login_data['user_id'],
                        'active_role': role
                    })

                    flash('Login verified successfully!', 'success')
                    response = make_response(redirect(url_for('dashboard')))
                    session_id = multi_tab_session.get_session_id()
                    response.set_cookie('multi_tab_session_id', session_id, httponly=True, secure=False)
                    return response
                else:
                    flash('Session expired. Please login again.', 'danger')
                    return redirect(url_for('login'))
        else:
            flash(message, 'danger')
    
    return render_template('auth/verify_otp.html', email=email, purpose=purpose)

@app.route('/resend-otp/<email>/<purpose>', methods=['POST'])
def resend_otp(email, purpose='password_reset'):
    """Resend OTP with cooldown check"""
    user = users_collection.find_one({'email': email})
    
    if not user:
        flash('Email not found.', 'danger')
        return redirect(url_for('forgot_password'))
    
    # Check cooldown period
    if not can_resend_otp(email, purpose, cooldown_minutes=1):
        flash('Please wait 1 minute before requesting a new OTP.', 'warning')
        return redirect(url_for('verify_otp', email=email, purpose=purpose))
    
    otp = generate_otp(6)
    expiry_minutes = 5 if purpose == 'login_2fa' else 10
    store_otp(email, otp, purpose, expiry_minutes=expiry_minutes)
    
    if send_otp_email(email, otp, purpose):
        flash('New OTP sent to your email.', 'success')
    else:
        flash('Error sending email. Please try again.', 'danger')
    
    return redirect(url_for('verify_otp', email=email, purpose=purpose))

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session:
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password'))
        
        users_collection.update_one(
            {'email': session['reset_email']},
            {'$set': {'password': hash_password(password)},
             '$unset': {'reset_otp': '', 'otp_expiry': ''}}
        )
        
        session.pop('reset_email', None)
        flash('Password reset successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('auth/reset_password.html')

@app.route('/logout')
def logout():
    # Check if logging out specific role or all
    logout_role = request.args.get('role')
    if logout_role and 'users' in session and logout_role in session['users']:
        # Logout specific role
        del session['users'][logout_role]
        if session.get('active_role') == logout_role:
            # If logging out active role, switch to another or clear
            remaining_roles = list(session['users'].keys())
            if remaining_roles:
                session['active_role'] = remaining_roles[0]
            else:
                session.pop('active_role', None)
                session.pop('users', None)
        flash(f'Logged out from {logout_role} role.', 'info')
    else:
        # Clear all user-specific session data for this tab only
        session_id = multi_tab_session.get_session_id()
        multi_tab_session.clear_session_data(session_id)

        # Clear Flask session
        session.clear()
        flash('You have been logged out from all roles.', 'info')

    # Create response and remove the session cookie if no users left
    response = make_response(redirect(url_for('login')))
    if 'users' not in session or not session['users']:
        response.delete_cookie('multi_tab_session_id')
    else:
        # Ensure cookie is set for remaining sessions
        session_id = multi_tab_session.get_session_id()
        response.set_cookie('multi_tab_session_id', session_id, httponly=True, secure=False)
    return response

@app.route('/switch-role/<role>')
@login_required
def switch_role(role):
    if role in session.get('users', {}):
        # Update multi-tab session for per-tab isolation
        user_data = session['users'][role]
        session_id = multi_tab_session.get_session_id()
        multi_tab_session.set_user_data(session_id, {
            'user_id': user_data['user_id'],
            'active_role': role
        })

        flash(f'Switched to {role} dashboard.', 'success')
        return redirect(url_for('dashboard'))

    flash('Invalid role selection.', 'danger')
    return redirect(url_for('dashboard'))



@app.route('/dashboard')
@login_required
def dashboard():
    # Get role from multi-tab session for per-tab isolation
    active_role = get_current_active_role()

    if not active_role or active_role not in session.get('users', {}):
        flash('Invalid session. Please login again.', 'warning')
        return redirect(url_for('login'))

    role = active_role
    user_id = session['users'][active_role]['user_id']


    
    stats = {}
    
    if role == 'admin':
        # Get admin wallet balance
        payment_settings = payment_settings_collection.find_one()
        wallet_balance = payment_settings.get('amount', 0) if payment_settings else 0
        
        stats = {
            'total_users': users_collection.count_documents({}),
            'total_products': products_collection.count_documents({}),
            'total_orders': orders_collection.count_documents({}),
            'pending_orders': orders_collection.count_documents({'status': 'pending'}),
            'total_suppliers': users_collection.count_documents({'role': 'supplier'}),
            'low_stock_products': products_collection.count_documents({'stock': {'$lt': 10}}),
            'wallet_balance': wallet_balance
        }
        recent_orders = list(orders_collection.find().sort('created_at', -1).limit(5))
        recent_users = list(users_collection.find().sort('created_at', -1).limit(5))
        return render_template('dashboard/admin.html', stats=stats, recent_orders=recent_orders, recent_users=recent_users)
    
    elif role == 'manager':
        stats = {
            'total_staff': users_collection.count_documents({'role': 'staff', 'manager_id': user_id}),
            'pending_requests': requests_collection.count_documents({'manager_id': user_id, 'status': 'pending'}),
            'total_orders': orders_collection.count_documents({'manager_id': user_id}),
            'total_suppliers': users_collection.count_documents({'role': 'supplier'})
        }
        pending_requests = list(requests_collection.find({'manager_id': user_id, 'status': 'pending'}).limit(5))

        # Ensure items field exists and is a list
        for req in pending_requests:
            if 'items' not in req or not isinstance(req.get('items'), list):
                req['items'] = []
            if 'created_at' not in req or not isinstance(req['created_at'], datetime):
                req['created_at'] = datetime.utcnow()
            if req.get('staff_id'):
                try:
                    staff = users_collection.find_one({'_id': ObjectId(req['staff_id'])})
                    req['staff_name'] = staff['username'] if staff else 'Unknown'
                except:
                    staff = users_collection.find_one({'_id': req['staff_id']})
                    req['staff_name'] = staff['username'] if staff else 'Unknown'
            else:
                req['staff_name'] = 'Unknown'

        # Get additional data for dashboard sections
        my_staff = list(users_collection.find({'role': 'staff', 'manager_id': user_id}).limit(5))
        suppliers = list(users_collection.find({'role': 'supplier'}).limit(5))

        # Get cart items
        session_id = multi_tab_session.get_session_id()
        user_data = multi_tab_session.get_user_data(session_id)
        cart_user_id = user_data.get('user_id') or user_id
        cart_items = list(cart_collection.find({'user_id': cart_user_id}).limit(5))

        # Enrich cart items with product details
        for item in cart_items:
            if item.get('product_id'):
                product_id_obj = safe_objectid(item['product_id'])
                if product_id_obj:
                    product = products_collection.find_one({'_id': product_id_obj})
                    if product:
                        item['product'] = product
                        item['subtotal'] = product['price'] * item['quantity']

        # Get recent orders
        recent_orders = list(orders_collection.find({'manager_id': user_id}).sort('created_at', -1).limit(5))

        # Enrich orders with supplier info
        for order in recent_orders:
            if order.get('supplier_id') and order['supplier_id'] != 'unknown':
                try:
                    supplier = users_collection.find_one({'_id': ObjectId(order['supplier_id'])})
                except:
                    supplier = users_collection.find_one({'_id': order['supplier_id']})
                order['supplier_name'] = supplier['company_name'] if supplier and supplier.get('company_name') else (supplier['username'] if supplier else 'Unknown')
            else:
                order['supplier_name'] = 'Unknown'

            # Ensure data types
            if 'items' not in order or not isinstance(order.get('items'), list):
                order['items'] = []
            if 'total' not in order or not isinstance(order['total'], (int, float)):
                order['total'] = 0.0
            else:
                order['total'] = float(order['total'])
            if 'created_at' not in order or not isinstance(order['created_at'], datetime):
                order['created_at'] = datetime.utcnow()

        return render_template('dashboard/manager.html', stats=stats, pending_requests=pending_requests,
                             my_staff=my_staff, suppliers=suppliers, cart_items=cart_items, recent_orders=recent_orders)
    
    elif role == 'staff':
        stats = {
            'my_requests': requests_collection.count_documents({'staff_id': user_id}),
            'pending_requests': requests_collection.count_documents({'staff_id': user_id, 'status': 'pending'}),
            'approved_requests': requests_collection.count_documents({'staff_id': user_id, 'status': 'approved'})
        }
        my_requests = list(requests_collection.find({'staff_id': user_id}).sort('created_at', -1).limit(5))
        
        # Ensure items field exists and is a list
        for req in my_requests:
            if 'items' not in req or not isinstance(req.get('items'), list):
                req['items'] = []
            if 'created_at' not in req or not isinstance(req['created_at'], datetime):
                req['created_at'] = datetime.utcnow()
        
        return render_template('dashboard/staff.html', stats=stats, my_requests=my_requests)
    
    elif role == 'supplier':
        # Get supplier's wallet balance
        supplier = users_collection.find_one({'_id': ObjectId(user_id)})
        wallet_balance = supplier.get('wallet_balance', 0) if supplier else 0
        
        stats = {
            'my_products': products_collection.count_documents({'supplier_id': user_id}),
            'pending_orders': orders_collection.count_documents({'supplier_id': user_id, 'status': 'pending'}),
            'completed_orders': orders_collection.count_documents({'supplier_id': user_id, 'status': 'completed'}),
            'total_orders': orders_collection.count_documents({'supplier_id': user_id}),
            'wallet_balance': wallet_balance
        }
        recent_orders = list(orders_collection.find({'supplier_id': user_id}).sort('created_at', -1).limit(5))
        
        # Ensure items field exists and is a list
        for order in recent_orders:
            if 'items' not in order or not isinstance(order.get('items'), list):
                order['items'] = []
            if 'total' not in order or not isinstance(order['total'], (int, float)):
                order['total'] = 0.0
            else:
                order['total'] = float(order['total'])
            if 'created_at' not in order or not isinstance(order['created_at'], datetime):
                order['created_at'] = datetime.utcnow()
        
        return render_template('dashboard/supplier.html', stats=stats, recent_orders=recent_orders)
    
    return render_template('dashboard/default.html')

# User Management Routes (Admin)
@app.route('/admin/users')
@role_required('admin')
def admin_users():
    role_filter = request.args.get('role', '')
    query = {}
    if role_filter:
        query['role'] = role_filter
    
    users = list(users_collection.find(query).sort('created_at', -1))
    return render_template('admin/users.html', users=users, role_filter=role_filter)

@app.route('/admin/users/add', methods=['GET', 'POST'])
@role_required('admin')
def admin_add_user():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        
        if users_collection.find_one({'email': email}):
            flash('Email already exists.', 'danger')
            return redirect(url_for('admin_add_user'))
        
        user_data = {
            'username': username,
            'email': email,
            'password': hash_password(password),
            'role': role,
            'created_at': datetime.utcnow(),
            'is_active': True
        }
        
        if role == 'supplier':
            user_data['company_name'] = request.form.get('company_name', '')
            user_data['contact_number'] = request.form.get('contact_number', '')
            user_data['address'] = request.form.get('address', '')
        elif role == 'staff':
            user_data['manager_id'] = request.form.get('manager_id', None)
        
        users_collection.insert_one(user_data)
        flash('User added successfully.', 'success')
        return redirect(url_for('admin_users'))
    
    managers = list(users_collection.find({'role': 'manager'}))
    return render_template('admin/add_user.html', managers=managers)

@app.route('/admin/users/edit/<user_id>', methods=['GET', 'POST'])
@role_required('admin')
def admin_edit_user(user_id):
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
    except:
        flash('Invalid user ID.', 'danger')
        return redirect(url_for('admin_users'))
    
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_users'))
    
    if request.method == 'POST':
        update_data = {
            'username': request.form.get('username'),
            'email': request.form.get('email'),
            'role': request.form.get('role'),
            'is_active': request.form.get('is_active') == 'on'
        }
        
        if request.form.get('password'):
            update_data['password'] = hash_password(request.form.get('password'))
        
        if update_data['role'] == 'supplier':
            update_data['company_name'] = request.form.get('company_name', '')
            update_data['contact_number'] = request.form.get('contact_number', '')
            update_data['address'] = request.form.get('address', '')
        elif update_data['role'] == 'staff':
            update_data['manager_id'] = request.form.get('manager_id', None)
        
        users_collection.update_one({'_id': ObjectId(user_id)}, {'$set': update_data})
        flash('User updated successfully.', 'success')
        return redirect(url_for('admin_users'))
    
    managers = list(users_collection.find({'role': 'manager'}))
    return render_template('admin/edit_user.html', user=user, managers=managers)

@app.route('/admin/users/delete/<user_id>', methods=['POST'])
@role_required('admin')
def admin_delete_user(user_id):
    user_id_obj = safe_objectid(user_id)
    if user_id_obj:
        users_collection.delete_one({'_id': user_id_obj})
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_users'))

# Category Management
@app.route('/categories')
@login_required
def categories():
    cats = list(categories_collection.find().sort('name', 1))
    return render_template('categories/list.html', categories=cats)

@app.route('/categories/add', methods=['GET', 'POST'])
@role_required('admin', 'manager')
def add_category():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description', '')
        
        # Case-insensitive duplicate check
        if categories_collection.find_one({'name': {'$regex': f'^{name}$', '$options': 'i'}}):
            flash('Category already exists. You cannot add this category.', 'danger')
            return render_template('categories/add.html', name=name, description=description)
        
        categories_collection.insert_one({
            'name': name,
            'description': description,
            'created_at': datetime.utcnow()
        })
        flash('Category added successfully.', 'success')
        return redirect(url_for('categories'))
    
    return render_template('categories/add.html')

@app.route('/categories/edit/<category_id>', methods=['GET', 'POST'])
@role_required('admin', 'manager')
def edit_category(category_id):
    category_id_obj = safe_objectid(category_id)
    if not category_id_obj:
        flash('Invalid category ID.', 'danger')
        return redirect(url_for('categories'))
    category = categories_collection.find_one({'_id': category_id_obj})
    if not category:
        flash('Category not found.', 'danger')
        return redirect(url_for('categories'))
    
    if request.method == 'POST':
        new_name = request.form.get('name')
        new_description = request.form.get('description', '')
        
        # Case-insensitive duplicate check (exclude current category)
        existing = categories_collection.find_one({
            'name': {'$regex': f'^{new_name}$', '$options': 'i'},
            '_id': {'$ne': category_id_obj}
        })
        if existing:
            flash('Category already exists. You cannot use this name.', 'danger')
            # Pass back the new values to preserve form data
            category['name'] = new_name
            category['description'] = new_description
            return render_template('categories/edit.html', category=category)
        
        categories_collection.update_one(
            {'_id': category_id_obj},
            {'$set': {
                'name': new_name,
                'description': new_description
            }}
        )
        flash('Category updated successfully.', 'success')
        return redirect(url_for('categories'))
    
    return render_template('categories/edit.html', category=category)

@app.route('/categories/delete/<category_id>', methods=['POST'])
@role_required('admin', 'manager')
def delete_category(category_id):
    category_id_obj = safe_objectid(category_id)
    if category_id_obj:
        categories_collection.delete_one({'_id': category_id_obj})
    flash('Category deleted successfully.', 'success')
    return redirect(url_for('categories'))

# Product Management
@app.route('/products')
@login_required
def products():
    category_filter = request.args.get('category', '')
    supplier_filter = request.args.get('supplier', '')
    search = request.args.get('search', '')
    
    query = {}
    if category_filter:
        query['category_id'] = category_filter
    if supplier_filter:
        query['supplier_id'] = supplier_filter
    if search:
        query['name'] = {'$regex': search, '$options': 'i'}
    
    session_id = multi_tab_session.get_session_id()
    user_data = multi_tab_session.get_user_data(session_id)
    if user_data.get('active_role') == 'supplier':
        query['supplier_id'] = user_data.get('user_id')
    
    prods = list(products_collection.find(query).sort('created_at', -1))
    cats = list(categories_collection.find())
    suppliers = list(users_collection.find({'role': 'supplier'}))
    
    # Enrich products with category and supplier names
    for prod in prods:
        if prod.get('category_id'):
            try:
                cat = categories_collection.find_one({'_id': ObjectId(prod['category_id'])})
                prod['category_name'] = cat['name'] if cat else 'Uncategorized'
            except:
                prod['category_name'] = 'Uncategorized'
        else:
            prod['category_name'] = 'Uncategorized'
        
        if prod.get('supplier_id'):
            try:
                sup = users_collection.find_one({'_id': ObjectId(prod['supplier_id'])})
                prod['supplier_name'] = sup['company_name'] if sup and sup.get('company_name') else (sup['username'] if sup else 'Unknown')
            except:
                # Try as string if ObjectId fails
                sup = users_collection.find_one({'_id': prod['supplier_id']})
                prod['supplier_name'] = sup['company_name'] if sup and sup.get('company_name') else (sup['username'] if sup else 'Unknown')
        else:
            prod['supplier_name'] = 'Unknown'
    
    return render_template('products/list.html', products=prods, categories=cats, suppliers=suppliers)

@app.route('/products/add', methods=['GET', 'POST'])
@role_required('admin', 'manager', 'supplier', 'staff')
def add_product():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description', '')
        price = float(request.form.get('price', 0))
        stock = int(request.form.get('stock', 0))
        category_id = request.form.get('category_id', '')
        sku = request.form.get('sku', '')
        
        # Handle supplier - use multi-tab session to get user_id
        tab_data = get_current_tab_data()
        active_role = tab_data.get('active_role') if tab_data else None
        if active_role == 'supplier':
            supplier_id = tab_data.get('user_id')
        else:
            supplier_id = request.form.get('supplier_id', '')
        
        # Handle image upload
        image_path = ''
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
                filename = f"{timestamp}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_path = f"uploads/{filename}"
        
        product_data = {
            'name': name,
            'description': description,
            'price': price,
            'stock': stock,
            'category_id': category_id,
            'supplier_id': supplier_id,
            'sku': sku,
            'image': image_path,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        
        products_collection.insert_one(product_data)
        flash('Product added successfully.', 'success')
        return redirect(url_for('products'))
    
    cats = list(categories_collection.find())
    suppliers = list(users_collection.find({'role': 'supplier'}))
    return render_template('products/add.html', categories=cats, suppliers=suppliers)

@app.route('/products/edit/<product_id>', methods=['GET', 'POST'])
@role_required('admin', 'manager', 'supplier', 'staff')
def edit_product(product_id):
    product_id_obj = safe_objectid(product_id)
    if not product_id_obj:
        flash('Invalid product ID.', 'danger')
        return redirect(url_for('products'))
    product = products_collection.find_one({'_id': product_id_obj})
    if not product:
        flash('Product not found.', 'danger')
        return redirect(url_for('products'))
    
    # Check supplier permission
    tab_data = get_current_tab_data()
    active_role = tab_data.get('active_role') if tab_data else None
    if active_role == 'supplier' and not safe_objectid_compare(product.get('supplier_id'), tab_data.get('user_id')):
        flash('You do not have permission to edit this product.', 'danger')
        return redirect(url_for('products'))
    
    if request.method == 'POST':
        update_data = {
            'name': request.form.get('name'),
            'description': request.form.get('description', ''),
            'price': float(request.form.get('price', 0)),
            'stock': int(request.form.get('stock', 0)),
            'category_id': request.form.get('category_id', ''),
            'sku': request.form.get('sku', ''),
            'updated_at': datetime.utcnow()
        }
        
        tab_data = get_current_tab_data()
        active_role = tab_data.get('active_role') if tab_data else None
        if active_role != 'supplier':
            update_data['supplier_id'] = request.form.get('supplier_id', '')
        
        # Handle image upload
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
                filename = f"{timestamp}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                update_data['image'] = f"uploads/{filename}"
        
        products_collection.update_one({'_id': product_id_obj}, {'$set': update_data})
        flash('Product updated successfully.', 'success')
        return redirect(url_for('products'))
    
    cats = list(categories_collection.find())
    suppliers = list(users_collection.find({'role': 'supplier'}))
    return render_template('products/edit.html', product=product, categories=cats, suppliers=suppliers)

@app.route('/products/delete/<product_id>', methods=['POST'])
@role_required('admin', 'manager', 'supplier', 'staff')
def delete_product(product_id):
    product_id_obj = safe_objectid(product_id)
    if not product_id_obj:
        flash('Invalid product ID.', 'danger')
        return redirect(url_for('products'))
    product = products_collection.find_one({'_id': product_id_obj})
    if not product:
        flash('Product not found.', 'danger')
        return redirect(url_for('products'))
    
    tab_data = get_current_tab_data()
    active_role = tab_data.get('active_role') if tab_data else None
    if active_role == 'supplier' and not safe_objectid_compare(product.get('supplier_id'), tab_data.get('user_id')):
        flash('You do not have permission to delete this product.', 'danger')
        return redirect(url_for('products'))
    
    products_collection.delete_one({'_id': product_id_obj})
    flash('Product deleted successfully.', 'success')
    return redirect(url_for('products'))

@app.route('/products/update-stock/<product_id>', methods=['POST'])
@role_required('admin', 'manager')
def update_stock(product_id):
    product_id_obj = safe_objectid(product_id)
    if not product_id_obj:
        flash('Invalid product ID.', 'danger')
        return redirect(url_for('products'))
    stock = int(request.form.get('stock', 0))
    products_collection.update_one(
        {'_id': product_id_obj},
        {'$set': {'stock': stock, 'updated_at': datetime.utcnow()}}
    )
    flash('Stock updated successfully.', 'success')
    return redirect(url_for('products'))

# Cart Management
@app.route('/cart')
@role_required('manager')
def view_cart():
    tab_data = get_current_tab_data()
    user_id = tab_data.get('user_id')
    if not user_id:
        flash('Please log in to view your cart.', 'warning')
        return redirect(url_for('login'))
    cart_items = list(cart_collection.find({'user_id': user_id}))

    # Enrich cart items with product details
    total = 0
    for item in cart_items:
        if item.get('product_id'):
            product_id_obj = safe_objectid(item['product_id'])
            if product_id_obj:
                product = products_collection.find_one({'_id': product_id_obj})
                if product:
                    item['product'] = product
                    item['subtotal'] = product['price'] * item['quantity']
                    total += item['subtotal']

    return render_template('cart/view.html', cart_items=cart_items, total=total)

@app.route('/cart/add', methods=['POST'])
@role_required('manager')
def add_to_cart():
    tab_data = get_current_tab_data()
    user_id = tab_data.get('user_id')
    if not user_id:
        flash('Please log in to add items to cart.', 'warning')
        return redirect(url_for('login'))
    product_id = request.form.get('product_id')
    quantity = int(request.form.get('quantity', 1))

    product_id_obj = safe_objectid(product_id)
    if not product_id_obj:
        flash('Invalid product ID.', 'danger')
        return redirect(url_for('products'))
    product = products_collection.find_one({'_id': product_id_obj})
    if not product:
        flash('Product not found.', 'danger')
        return redirect(url_for('products'))

    if product['stock'] < quantity:
        flash('Insufficient stock available.', 'danger')
        return redirect(url_for('products'))

    # Check if item already in cart
    existing = cart_collection.find_one({'user_id': user_id, 'product_id': product_id})
    if existing:
        new_quantity = existing['quantity'] + quantity
        if product['stock'] < new_quantity:
            flash('Insufficient stock available.', 'danger')
            return redirect(url_for('products'))
        cart_collection.update_one(
            {'_id': existing['_id']},
            {'$set': {'quantity': new_quantity}}
        )
    else:
        cart_collection.insert_one({
            'user_id': user_id,
            'product_id': product_id,
            'quantity': quantity,
            'added_at': datetime.utcnow()
        })

    flash('Product added to cart.', 'success')
    return redirect(url_for('products'))

@app.route('/cart/update/<item_id>', methods=['POST'])
@role_required('manager')
def update_cart(item_id):
    item_id_obj = safe_objectid(item_id)
    if not item_id_obj:
        flash('Invalid cart item ID.', 'danger')
        return redirect(url_for('view_cart'))
    quantity = int(request.form.get('quantity', 1))

    session_id = multi_tab_session.get_session_id()
    user_data = multi_tab_session.get_user_data(session_id)
    user_id = user_data.get('user_id') or session.get('user_id')
    if not user_id:
        flash('Please log in to update your cart.', 'warning')
        return redirect(url_for('login'))

    item = cart_collection.find_one({'_id': item_id_obj, 'user_id': user_id})
    if item:
        product_id_obj = safe_objectid(item.get('product_id'))
        if not product_id_obj:
            flash('Invalid product in cart.', 'danger')
            return redirect(url_for('view_cart'))
        product = products_collection.find_one({'_id': product_id_obj})
        if product and product['stock'] >= quantity:
            cart_collection.update_one(
                {'_id': item_id_obj},
                {'$set': {'quantity': quantity}}
            )
            flash('Cart updated.', 'success')
        else:
            flash('Insufficient stock available.', 'danger')

    return redirect(url_for('view_cart'))

@app.route('/cart/remove/<item_id>', methods=['POST'])
@role_required('manager')
def remove_from_cart(item_id):
    item_id_obj = safe_objectid(item_id)
    if not item_id_obj:
        flash('Invalid cart item ID.', 'danger')
        return redirect(url_for('view_cart'))

    tab_data = get_current_tab_data()
    user_id = tab_data.get('user_id')
    if not user_id:
        flash('Please log in to remove items from cart.', 'warning')
        return redirect(url_for('login'))

    item = cart_collection.find_one({'_id': item_id_obj, 'user_id': user_id})
    if item:
        cart_collection.delete_one({'_id': item_id_obj})
        flash('Item removed from cart.', 'success')
    else:
        flash('Item not found in your cart.', 'danger')
    return redirect(url_for('view_cart'))

@app.route('/cart/clear', methods=['POST'])
@role_required('manager')
def clear_cart():
    tab_data = get_current_tab_data()
    user_id = tab_data.get('user_id')
    if not user_id:
        flash('Please log in to clear your cart.', 'warning')
        return redirect(url_for('login'))
    cart_collection.delete_many({'user_id': user_id})
    flash('Cart cleared.', 'success')
    return redirect(url_for('view_cart'))

# Checkout - Display checkout page with payment options
@app.route('/cart/checkout')
@role_required('manager')
def checkout():
    tab_data = get_current_tab_data()
    user_id = tab_data.get('user_id')
    if not user_id:
        flash('Please log in to checkout.', 'warning')
        return redirect(url_for('login'))
    
    cart_items = list(cart_collection.find({'user_id': user_id}))

    if not cart_items:
        flash('Your cart is empty.', 'warning')
        return redirect(url_for('view_cart'))

    # Enrich cart items with product details and calculate total
    total = 0
    for item in cart_items:
        if item.get('product_id'):
            product_id_obj = safe_objectid(item['product_id'])
            if product_id_obj:
                product = products_collection.find_one({'_id': product_id_obj})
                if product:
                    item['product'] = product
                    item['subtotal'] = product['price'] * item['quantity']
                    total += item['subtotal']

    # Get payment settings for displaying payment details
    payment_settings = payment_settings_collection.find_one()
    
    return render_template('cart/checkout.html', cart_items=cart_items, total=total, payment_settings=payment_settings)

# Process Payment - Handle payment processing and order creation
@app.route('/cart/process-payment', methods=['POST'])
@role_required('manager')
def process_payment():
    tab_data = get_current_tab_data()
    user_id = tab_data.get('user_id')
    if not user_id:
        flash('Please log in to complete payment.', 'warning')
        return redirect(url_for('login'))
    
    # Get cart items
    cart_items = list(cart_collection.find({'user_id': user_id}))
    if not cart_items:
        flash('Your cart is empty.', 'warning')
        return redirect(url_for('view_cart'))
    
    # Get payment method
    payment_method = request.form.get('payment_method')
    transaction_id = request.form.get('transaction_id', '')
    upi_id = request.form.get('upi_id', '')
    
    # Validate payment method
    if not payment_method:
        flash('Please select a payment method.', 'danger')
        return redirect(url_for('checkout'))
    
    if payment_method not in ['upi', 'qr_code', 'bank_transfer']:
        flash('Invalid payment method.', 'danger')
        return redirect(url_for('checkout'))
    
    # Validate transaction ID
    if not transaction_id or not transaction_id.strip():
        flash('Please enter the Transaction ID / UTR Number.', 'danger')
        return redirect(url_for('checkout'))
    
    # Handle payment proof upload (for bank transfer)
    payment_proof_path = ''
    if 'payment_proof' in request.files:
        file = request.files['payment_proof']
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
            filename = f"{timestamp}_{filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            payment_proof_path = f"uploads/{filename}"
    
    # Calculate total
    total = 0
    for item in cart_items:
        if item.get('product_id'):
            product_id_obj = safe_objectid(item['product_id'])
            if product_id_obj:
                product = products_collection.find_one({'_id': product_id_obj})
                if product:
                    item['product'] = product
                    item['subtotal'] = product['price'] * item['quantity']
                    total += item['subtotal']
    
    # Group items by supplier
    supplier_orders = {}
    for item in cart_items:
        product_id_obj = safe_objectid(item.get('product_id'))
        if not product_id_obj:
            continue
        product = products_collection.find_one({'_id': product_id_obj})
        if product:
            supplier_id = product.get('supplier_id', 'unknown')
            if supplier_id not in supplier_orders:
                supplier_orders[supplier_id] = []
            supplier_orders[supplier_id].append({
                'product_id': item['product_id'],
                'product_name': product['name'],
                'quantity': item['quantity'],
                'price': product['price'],
                'subtotal': product['price'] * item['quantity']
            })
    
    # Create orders for each supplier
    created_orders = []
    for supplier_id, items in supplier_orders.items():
        order_total = sum(item['subtotal'] for item in items)
        order_data = {
            'order_number': f"ORD-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{supplier_id[:4] if supplier_id != 'unknown' else 'UNKN'}",
            'manager_id': user_id,
            'supplier_id': supplier_id,
            'items': items,
            'total': order_total,
            'status': 'pending',
            'payment_method': payment_method,
            'transaction_id': transaction_id.strip(),
            'upi_id': upi_id,
            'payment_proof': payment_proof_path,
            'payment_status': 'completed',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        result = orders_collection.insert_one(order_data)
        created_orders.append(str(result.inserted_id))
    
    # Credit admin wallet with the payment amount
    payment_settings = payment_settings_collection.find_one()
    current_balance = payment_settings.get('amount', 0) if payment_settings else 0
    new_balance = current_balance + total
    
    # Create payment record for the incoming payment
    payment_record = {
        'payment_number': f"PAY-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:8]}",
        'amount': total,
        'balance_before': current_balance,
        'balance_after': new_balance,
        'payment_method': payment_method,
        'status': 'completed',
        'payment_type': 'customer_payment',
        'transaction_id': transaction_id.strip(),
        'order_ids': created_orders,
        'created_at': datetime.utcnow()
    }
    payments_collection.insert_one(payment_record)
    
    # Update admin wallet balance
    if payment_settings:
        payment_settings_collection.update_one(
            {'_id': payment_settings['_id']},
            {'$set': {'amount': new_balance, 'updated_at': datetime.utcnow()}}
        )
    else:
        payment_settings_collection.insert_one({
            'amount': new_balance,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        })
    
    # Clear cart after successful payment
    cart_collection.delete_many({'user_id': user_id})
    
    # Create notification
    tab_data = get_current_tab_data()
    notice_data = {
        'title': 'Payment Received',
        'content': f'Payment of ₹{total:.2f} received via {payment_method.replace("_", " ").title()}. Transaction ID: {transaction_id}. New wallet balance: ₹{new_balance:.2f}',
        'author_id': user_id,
        'target_roles': ['admin'],
        'priority': 'normal',
        'created_at': datetime.utcnow(),
        'updated_at': datetime.utcnow()
    }
    notices_collection.insert_one(notice_data)
    
    flash(f'Payment successful! ₹{total:.2f} has been credited to your account. Transaction ID: {transaction_id}', 'success')
    return redirect(url_for('manager_orders'))

# Order Management (Manager placing orders to suppliers)
@app.route('/orders/place', methods=['POST'])
@role_required('manager')
def place_order():
    tab_data = get_current_tab_data()
    user_id = tab_data.get('user_id')
    if not user_id:
        flash('Please log in to place orders.', 'warning')
        return redirect(url_for('login'))
    cart_items = list(cart_collection.find({'user_id': user_id}))

    if not cart_items:
        flash('Cart is empty.', 'warning')
        return redirect(url_for('view_cart'))

    # Group items by supplier
    supplier_orders = {}
    for item in cart_items:
        product_id_obj = safe_objectid(item.get('product_id'))
        if not product_id_obj:
            continue
        product = products_collection.find_one({'_id': product_id_obj})
        if product:
            supplier_id = product.get('supplier_id', 'unknown')
            if supplier_id not in supplier_orders:
                supplier_orders[supplier_id] = []
            supplier_orders[supplier_id].append({
                'product_id': item['product_id'],
                'product_name': product['name'],
                'quantity': item['quantity'],
                'price': product['price'],
                'subtotal': product['price'] * item['quantity']
            })

    # Create orders for each supplier
    for supplier_id, items in supplier_orders.items():
        total = sum(item['subtotal'] for item in items)
        order_data = {
            'order_number': f"ORD-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{supplier_id[:4] if supplier_id != 'unknown' else 'UNKN'}",
            'manager_id': user_id,
            'supplier_id': supplier_id,
            'items': items,
            'total': total,
            'status': 'pending',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        orders_collection.insert_one(order_data)

    # Clear cart
    cart_collection.delete_many({'user_id': user_id})

    flash('Orders placed successfully.', 'success')
    return redirect(url_for('manager_orders'))

@app.route('/manager/orders')
@role_required('manager')
def manager_orders():
    tab_data = get_current_tab_data()
    active_role = tab_data.get('active_role') if tab_data else None
    user_id = tab_data.get('user_id')
    status_filter = request.args.get('status', '')

    query = {'manager_id': user_id}
    if status_filter:
        query['status'] = status_filter

    orders = list(orders_collection.find(query).sort('created_at', -1))

    # Enrich with supplier info
    for order in orders:
        if order.get('supplier_id') and order['supplier_id'] != 'unknown':
            try:
                supplier = users_collection.find_one({'_id': ObjectId(order['supplier_id'])})
            except:
                supplier = users_collection.find_one({'_id': order['supplier_id']})
            order['supplier_name'] = supplier['company_name'] if supplier and supplier.get('company_name') else (supplier['username'] if supplier else 'Unknown')
        else:
            order['supplier_name'] = 'Unknown'

    # Ensure data types for template rendering
    for order in orders:
        if 'items' not in order or not isinstance(order.get('items'), list):
            order['items'] = []
        if 'total' not in order or not isinstance(order['total'], (int, float)):
            order['total'] = 0.0
        else:
            order['total'] = float(order['total'])

        if 'created_at' not in order or not isinstance(order['created_at'], datetime):
            order['created_at'] = datetime.utcnow()

    return render_template('orders/manager_orders.html', orders=orders)

# Supplier Order Management
@app.route('/supplier/orders')
@role_required('supplier')
def supplier_orders():
    tab_data = get_current_tab_data()
    active_role = tab_data.get('active_role') if tab_data else None
    user_id = tab_data.get('user_id')
    status_filter = request.args.get('status', '')

    query = {'supplier_id': user_id}
    if status_filter:
        query['status'] = status_filter

    orders = list(orders_collection.find(query).sort('created_at', -1))

    # Enrich with manager info
    for order in orders:
        if order.get('manager_id'):
            try:
                manager = users_collection.find_one({'_id': ObjectId(order['manager_id'])})
            except:
                manager = users_collection.find_one({'_id': order['manager_id']})
            order['manager_name'] = manager['username'] if manager else 'Unknown'
        else:
            order['manager_name'] = 'Unknown'

    # Ensure data types for template rendering
    for order in orders:
        if 'items' not in order or not isinstance(order.get('items'), list):
            order['items'] = []
        if 'total' not in order or not isinstance(order['total'], (int, float)):
            order['total'] = 0.0
        else:
            order['total'] = float(order['total'])
        if 'created_at' not in order or not isinstance(order['created_at'], datetime):
            order['created_at'] = datetime.utcnow()

    return render_template('orders/supplier_orders.html', orders=orders)

@app.route('/supplier/orders/<order_id>/approve', methods=['POST'])
@role_required('supplier')
def approve_order(order_id):
    order_id_obj = safe_objectid(order_id)
    if not order_id_obj:
        flash('Invalid order ID.', 'danger')
        return redirect(url_for('supplier_orders'))
    order = orders_collection.find_one({'_id': order_id_obj})

    tab_data = get_current_tab_data()
    if order and safe_objectid_compare(order['supplier_id'], tab_data.get('user_id')):
        orders_collection.update_one(
            {'_id': order_id_obj},
            {'$set': {'status': 'approved', 'updated_at': datetime.utcnow()}}
        )
        flash('Order approved.', 'success')
    else:
        flash('Order not found or permission denied.', 'danger')

    return redirect(url_for('supplier_orders'))

@app.route('/supplier/orders/<order_id>/complete', methods=['POST'])
@role_required('supplier')
def complete_order(order_id):
    order_id_obj = safe_objectid(order_id)
    if not order_id_obj:
        flash('Invalid order ID.', 'danger')
        return redirect(url_for('supplier_orders'))
    order = orders_collection.find_one({'_id': order_id_obj})
    
    active_role = session.get('active_role')
    if order and safe_objectid_compare(order['supplier_id'], session['users'][active_role]['user_id']):
        # Update stock levels
        for item in order['items']:
            product_id_obj = safe_objectid(item.get('product_id'))
            if not product_id_obj:
                continue
            products_collection.update_one(
                {'_id': product_id_obj},
                {'$inc': {'stock': -item['quantity']}, '$set': {'updated_at': datetime.utcnow()}}
            )

        orders_collection.update_one(
            {'_id': order_id_obj},
            {'$set': {'status': 'completed', 'completed_at': datetime.utcnow(), 'updated_at': datetime.utcnow()}}
        )
        flash('Order completed and stock updated.', 'success')
    else:
        flash('Order not found or permission denied.', 'danger')
    
    return redirect(url_for('supplier_orders'))

@app.route('/supplier/orders/<order_id>/reject', methods=['POST'])
@role_required('supplier')
def reject_order(order_id):
    order_id_obj = safe_objectid(order_id)
    if not order_id_obj:
        flash('Invalid order ID.', 'danger')
        return redirect(url_for('supplier_orders'))
    order = orders_collection.find_one({'_id': order_id_obj})

    tab_data = get_current_tab_data()
    active_role = tab_data.get('active_role') if tab_data else None
    if order and safe_objectid_compare(order['supplier_id'], tab_data.get('user_id')):
        reason = request.form.get('reason', '')
        orders_collection.update_one(
            {'_id': order_id_obj},
            {'$set': {'status': 'rejected', 'rejection_reason': reason, 'updated_at': datetime.utcnow()}}
        )
        flash('Order rejected.', 'success')
    else:
        flash('Order not found or permission denied.', 'danger')

    return redirect(url_for('supplier_orders'))

# Staff Request System
@app.route('/requests')
@login_required
def requests_list():
    tab_data = get_current_tab_data()
    active_role = tab_data.get('active_role') if tab_data else None
    if not active_role or active_role not in session.get('users', {}):
        flash('Invalid session.', 'warning')
        return redirect(url_for('login'))
    user_id = tab_data.get('user_id')
    role = active_role
    
    if role == 'staff':
        query = {'staff_id': user_id}
    elif role == 'manager':
        query = {'manager_id': user_id}
    elif role == 'admin':
        query = {}
    else:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    status_filter = request.args.get('status', '')
    if status_filter:
        query['status'] = status_filter
    
    reqs = list(requests_collection.find(query).sort('created_at', -1))
    
    # Enrich with user info
    for req in reqs:
        if req.get('staff_id'):
            try:
                staff = users_collection.find_one({'_id': ObjectId(req['staff_id'])})
                req['staff_name'] = staff['username'] if staff else 'Unknown'
            except:
                staff = users_collection.find_one({'_id': req['staff_id']})
                req['staff_name'] = staff['username'] if staff else 'Unknown'
        else:
            req['staff_name'] = 'Unknown'
        
        if req.get('manager_id'):
            try:
                manager = users_collection.find_one({'_id': ObjectId(req['manager_id'])})
                req['manager_name'] = manager['username'] if manager else 'Unknown'
            except:
                manager = users_collection.find_one({'_id': req['manager_id']})
                req['manager_name'] = manager['username'] if manager else 'Unknown'
        else:
            req['manager_name'] = 'Unknown'
        
        # Ensure items field exists and is a list
        if 'items' not in req or not isinstance(req.get('items'), list):
            req['items'] = []
        if 'created_at' not in req or not isinstance(req['created_at'], datetime):
            req['created_at'] = datetime.utcnow()
    
    return render_template('requests/list.html', requests=reqs, role=role)

@app.route('/requests/create', methods=['GET', 'POST'])
@role_required('staff')
def create_request():
    if request.method == 'POST':
        tab_data = get_current_tab_data()
        active_role = tab_data.get('active_role') if tab_data else None
        user_id = tab_data.get('user_id')
        user_id_obj = safe_objectid(user_id)
        if not user_id_obj:
            flash('Invalid user session.', 'danger')
            return redirect(url_for('requests_list'))
        user = users_collection.find_one({'_id': user_id_obj})
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('requests_list'))

        manager_id = user.get('manager_id')
        if not manager_id:
            flash('You are not assigned to a manager.', 'danger')
            return redirect(url_for('requests_list'))
        
        items = []
        product_ids = request.form.getlist('product_id[]')
        quantities = request.form.getlist('quantity[]')
        
        for pid, qty in zip(product_ids, quantities):
            if pid and qty:
                product_id_obj = safe_objectid(pid)
                if not product_id_obj:
                    continue
                product = products_collection.find_one({'_id': product_id_obj})
                if product:
                    items.append({
                        'product_id': pid,
                        'product_name': product['name'],
                        'quantity': int(qty)
                    })
        
        if not items:
            flash('Please add at least one item.', 'danger')
            return redirect(url_for('create_request'))
        
        request_data = {
            'request_number': f"REQ-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            'staff_id': user_id,
            'manager_id': manager_id,
            'items': items,
            'reason': request.form.get('reason', ''),
            'status': 'pending',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        
        requests_collection.insert_one(request_data)
        flash('Request submitted successfully.', 'success')
        return redirect(url_for('requests_list'))
    
    prods = list(products_collection.find({'stock': {'$gt': 0}}))
    return render_template('requests/create.html', products=prods)

@app.route('/requests/<request_id>/approve', methods=['POST'])
@role_required('manager')
def approve_request(request_id):
    request_id_obj = safe_objectid(request_id)
    if not request_id_obj:
        flash('Invalid request ID.', 'danger')
        return redirect(url_for('requests_list'))
    req = requests_collection.find_one({'_id': request_id_obj})
    
    active_role = session.get('active_role')
    if req and safe_objectid_compare(req['manager_id'], session['users'][active_role]['user_id']):
        requests_collection.update_one(
            {'_id': request_id_obj},
            {'$set': {'status': 'approved', 'updated_at': datetime.utcnow()}}
        )
        flash('Request approved.', 'success')
    else:
        flash('Request not found or permission denied.', 'danger')
    
    return redirect(url_for('requests_list'))

@app.route('/requests/<request_id>/reject', methods=['POST'])
@role_required('manager')
def reject_request(request_id):
    request_id_obj = safe_objectid(request_id)
    if not request_id_obj:
        flash('Invalid request ID.', 'danger')
        return redirect(url_for('requests_list'))
    req = requests_collection.find_one({'_id': request_id_obj})
    
    active_role = session.get('active_role')
    if req and safe_objectid_compare(req['manager_id'], session['users'][active_role]['user_id']):
        reason = request.form.get('reason', '')
        requests_collection.update_one(
            {'_id': request_id_obj},
            {'$set': {'status': 'rejected', 'rejection_reason': reason, 'updated_at': datetime.utcnow()}}
        )
        flash('Request rejected.', 'success')
    else:
        flash('Request not found or permission denied.', 'danger')
    
    return redirect(url_for('requests_list'))

@app.route('/requests/<request_id>/fulfill', methods=['POST'])
@role_required('staff', 'manager')
def fulfill_request(request_id):
    request_id_obj = safe_objectid(request_id)
    if not request_id_obj:
        flash('Invalid request ID.', 'danger')
        return redirect(url_for('requests_list'))
    req = requests_collection.find_one({'_id': request_id_obj})
    
    if req and req['status'] == 'approved':
        # Update stock levels
        for item in req['items']:
            product_id_obj = safe_objectid(item.get('product_id'))
            if not product_id_obj:
                continue
            products_collection.update_one(
                {'_id': product_id_obj},
                {'$inc': {'stock': -item['quantity']}, '$set': {'updated_at': datetime.utcnow()}}
            )
        
        requests_collection.update_one(
            {'_id': request_id_obj},
            {'$set': {'status': 'fulfilled', 'fulfilled_at': datetime.utcnow(), 'updated_at': datetime.utcnow()}}
        )
        flash('Request fulfilled and stock updated.', 'success')
    else:
        flash('Request not found or not approved.', 'danger')
    
    return redirect(url_for('requests_list'))

# Notice System
@app.route('/notices')
@login_required
def notices():
    tab_data = get_current_tab_data()
    active_role = tab_data.get('active_role') if tab_data else None
    role = active_role
    
    query = {'$or': [{'target_roles': {'$in': [role]}}, {'target_roles': {'$size': 0}}, {'target_roles': {'$exists': False}}]}
    
    if role == 'admin':
        query = {}
    
    notice_list = list(notices_collection.find(query).sort('created_at', -1))
    
    # Enrich with author info
    for notice in notice_list:
        if notice.get('author_id'):
            try:
                author = users_collection.find_one({'_id': ObjectId(notice['author_id'])})
            except:
                author = users_collection.find_one({'_id': notice['author_id']})
            notice['author_name'] = author['username'] if author else 'System'
        else:
            notice['author_name'] = 'System'
    
    return render_template('notices/list.html', notices=notice_list)

@app.route('/notices/create', methods=['GET', 'POST'])
@role_required('admin', 'manager')
def create_notice():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        target_roles = request.form.getlist('target_roles')
        priority = request.form.get('priority', 'normal')
        
        tab_data = get_current_tab_data()
        active_role = tab_data.get('active_role') if tab_data else None
        notice_data = {
            'title': title,
            'content': content,
            'author_id': tab_data.get('user_id'),
            'target_roles': target_roles,
            'priority': priority,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        
        notices_collection.insert_one(notice_data)
        flash('Notice created successfully.', 'success')
        return redirect(url_for('notices'))
    
    return render_template('notices/create.html')

@app.route('/notices/<notice_id>')
@login_required
def view_notice(notice_id):
    notice_id_obj = safe_objectid(notice_id)
    if not notice_id_obj:
        flash('Invalid notice ID.', 'danger')
        return redirect(url_for('notices'))
    notice = notices_collection.find_one({'_id': notice_id_obj})
    if not notice:
        flash('Notice not found.', 'danger')
        return redirect(url_for('notices'))
    
    if notice:
        if notice.get('author_id'):
            try:
                author = users_collection.find_one({'_id': ObjectId(notice['author_id'])})
            except:
                author = users_collection.find_one({'_id': notice['author_id']})
            notice['author_name'] = author['username'] if author else 'System'
        else:
            notice['author_name'] = 'System'
    
    return render_template('notices/view.html', notice=notice)

@app.route('/notices/edit/<notice_id>', methods=['GET', 'POST'])
@role_required('admin', 'manager')
def edit_notice(notice_id):
    notice_id_obj = safe_objectid(notice_id)
    if not notice_id_obj:
        flash('Invalid notice ID.', 'danger')
        return redirect(url_for('notices'))
    notice = notices_collection.find_one({'_id': notice_id_obj})
    if not notice:
        flash('Notice not found.', 'danger')
        return redirect(url_for('notices'))
    
    tab_data = get_current_tab_data()
    active_role = tab_data.get('active_role') if tab_data else None
    if active_role != 'admin' and not safe_objectid_compare(notice.get('author_id'), tab_data.get('user_id')):
        flash('You do not have permission to edit this notice.', 'danger')
        return redirect(url_for('notices'))
    
    if request.method == 'POST':
        notices_collection.update_one(
            {'_id': notice_id_obj},
            {'$set': {
                'title': request.form.get('title'),
                'content': request.form.get('content'),
                'target_roles': request.form.getlist('target_roles'),
                'priority': request.form.get('priority', 'normal'),
                'updated_at': datetime.utcnow()
            }}
        )
        flash('Notice updated successfully.', 'success')
        return redirect(url_for('notices'))
    
    return render_template('notices/edit.html', notice=notice)

@app.route('/notices/delete/<notice_id>', methods=['POST'])
@role_required('admin', 'manager')
def delete_notice(notice_id):
    notice_id_obj = safe_objectid(notice_id)
    if not notice_id_obj:
        flash('Invalid notice ID.', 'danger')
        return redirect(url_for('notices'))
    notice = notices_collection.find_one({'_id': notice_id_obj})
    if not notice:
        flash('Notice not found.', 'danger')
        return redirect(url_for('notices'))

    tab_data = get_current_tab_data()
    active_role = tab_data.get('active_role') if tab_data else None
    if active_role != 'admin' and not safe_objectid_compare(notice.get('author_id'), tab_data.get('user_id')):
        flash('You do not have permission to delete this notice.', 'danger')
        return redirect(url_for('notices'))

    notices_collection.delete_one({'_id': notice_id_obj})
    flash('Notice deleted successfully.', 'success')
    return redirect(url_for('notices'))

# Admin Reports
@app.route('/admin/reports')
@role_required('admin')
def admin_reports():
    # Get date range
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
    query = {}
    if start_date:
        query['created_at'] = {'$gte': datetime.strptime(start_date, '%Y-%m-%d')}
    if end_date:
        if 'created_at' in query:
            query['created_at']['$lte'] = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
        else:
            query['created_at'] = {'$lte': datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)}
    
    # Order statistics
    total_orders = orders_collection.count_documents(query)
    pending_orders = orders_collection.count_documents({**query, 'status': 'pending'})
    completed_orders = orders_collection.count_documents({**query, 'status': 'completed'})
    
    # Calculate total revenue
    pipeline = [
        {'$match': {**query, 'status': 'completed'}},
        {'$group': {'_id': None, 'total': {'$sum': '$total'}}}
    ]
    revenue_result = list(orders_collection.aggregate(pipeline))
    total_revenue = revenue_result[0]['total'] if revenue_result else 0
    
    # Top products
    product_pipeline = [
        {'$match': query},
        {'$unwind': '$items'},
        {'$group': {'_id': '$items.product_name', 'total_quantity': {'$sum': '$items.quantity'}}},
        {'$sort': {'total_quantity': -1}},
        {'$limit': 10}
    ]
    top_products = list(orders_collection.aggregate(product_pipeline))
    
    # Low stock products
    low_stock = list(products_collection.find({'stock': {'$lt': 10}}).sort('stock', 1).limit(10))
    
    stats = {
        'total_orders': total_orders,
        'pending_orders': pending_orders,
        'completed_orders': completed_orders,
        'total_revenue': total_revenue,
        'top_products': top_products,
        'low_stock_products': low_stock
    }
    
    return render_template('admin/reports.html', stats=stats, start_date=start_date, end_date=end_date)

# Payment Settings
@app.route('/admin/payment-settings', methods=['GET', 'POST'])
@role_required('admin')
def payment_settings():
    # Get existing payment settings (only one document)
    payment_settings = payment_settings_collection.find_one()
    
    if request.method == 'POST':
        # Determine the action: 'add' or 'edit'
        action = request.form.get('action', 'add')
        
        # UPI Settings
        upi_id = request.form.get('upi_id', '')
        
        # Bank Transfer Settings
        bank_name = request.form.get('bank_name', '')
        account_number = request.form.get('account_number', '')
        ifsc_code = request.form.get('ifsc_code', '')
        account_holder_name = request.form.get('account_holder_name', '')
        
        # QR Code upload
        qr_code_path = payment_settings.get('qr_code') if payment_settings else ''
        if 'qr_code' in request.files:
            file = request.files['qr_code']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
                filename = f"{timestamp}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                qr_code_path = f"uploads/{filename}"
        
        # Payment methods enabled/disabled
        upi_enabled = 'upi_enabled' in request.form
        bank_transfer_enabled = 'bank_transfer_enabled' in request.form
        qr_code_enabled = 'qr_code_enabled' in request.form
        
        # Get existing amount
        existing_amount = payment_settings.get('amount', 0) if payment_settings else 0
        existing_payment_id = payment_settings.get('current_payment_id') if payment_settings else None
        new_amount = existing_amount
        
        # Process amount based on action
        amount_flash_message = ''
        new_payment_record_id = None
        
        if action == 'edit':
            # Edit mode: Replace the existing amount with a new value
            new_amount_input = request.form.get('new_amount')
            if new_amount_input:
                try:
                    new_amount_value = float(new_amount_input)
                    if new_amount_value >= 0:
                        # Get current payment record to mark as not latest
                        if existing_payment_id:
                            payments_collection.update_one(
                                {'_id': existing_payment_id},
                                {'$set': {'is_latest': False, 'replaced_at': datetime.utcnow()}}
                            )
                        
                        # Get version number from last payment
                        last_payment = payments_collection.find_one(
                            {'replaced_by_payment_id': {'$exists': False}},
                            sort=[('version', -1)]
                        )
                        new_version = (last_payment.get('version', 0) + 1) if last_payment else 1
                        
                        # Create NEW payment record with the updated amount
                        payment_record = {
                            'payment_number': f"PAY-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:8]}",
                            'amount': new_amount_value,
                            'balance_before': existing_amount,
                            'balance_after': new_amount_value,
                            'payment_method': 'manual',
                            'status': 'completed',
                            'version': new_version,
                            'previous_payment_id': existing_payment_id,
                            'is_latest': True,
                            'action_type': 'edit',
                            'created_at': datetime.utcnow(),
                            'created_by': get_current_tab_data().get('user_id') if get_current_tab_data() else None
                        }
                        result = payments_collection.insert_one(payment_record)
                        new_payment_record_id = result.inserted_id
                        
                        # Update old payment with reference to new payment
                        if existing_payment_id:
                            payments_collection.update_one(
                                {'_id': existing_payment_id},
                                {'$set': {'replaced_by_payment_id': new_payment_record_id}}
                            )
                        
                        new_amount = new_amount_value
                        
                        # Create notice for the edit
                        tab_data = get_current_tab_data()
                        admin_user_id = tab_data.get('user_id') if tab_data else None
                        
                        notice_data = {
                            'title': 'Amount Edited Successfully',
                            'content': f'Your payment amount has been edited from ₹{existing_amount} to ₹{new_amount_value}. A new payment record has been created for audit purposes.',
                            'author_id': admin_user_id,
                            'target_roles': ['admin'],
                            'priority': 'normal',
                            'created_at': datetime.utcnow(),
                            'updated_at': datetime.utcnow()
                        }
                        notices_collection.insert_one(notice_data)
                        
                        amount_flash_message = f' Amount edited! Old record preserved, new record created with ₹{new_amount_value}.'
                    else:
                        flash('Amount must be 0 or greater.', 'danger')
                        return redirect(url_for('payment_settings'))
                except ValueError:
                    flash('Invalid amount format.', 'danger')
                    return redirect(url_for('payment_settings'))
        else:
            # Add mode (default): Add new amount to existing balance
            amount_to_add = request.form.get('amount')
            if amount_to_add:
                try:
                    amount_value = float(amount_to_add)
                    if amount_value > 0:
                        new_amount = existing_amount + amount_value
                        
                        # Get version number
                        last_payment = payments_collection.find_one(
                            {'replaced_by_payment_id': {'$exists': False}},
                            sort=[('version', -1)]
                        )
                        new_version = (last_payment.get('version', 0) + 1) if last_payment else 1
                        
                        # Create payment record for the added amount
                        payment_record = {
                            'payment_number': f"PAY-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:8]}",
                            'amount': amount_value,
                            'balance_before': existing_amount,
                            'balance_after': new_amount,
                            'payment_method': 'manual',
                            'status': 'completed',
                            'version': new_version,
                            'previous_payment_id': existing_payment_id,
                            'is_latest': True,
                            'action_type': 'add',
                            'created_at': datetime.utcnow(),
                            'created_by': get_current_tab_data().get('user_id') if get_current_tab_data() else None
                        }
                        result = payments_collection.insert_one(payment_record)
                        new_payment_record_id = result.inserted_id
                        
                        # Update old payment to not be latest
                        if existing_payment_id:
                            payments_collection.update_one(
                                {'_id': existing_payment_id},
                                {'$set': {'is_latest': False, 'replaced_at': datetime.utcnow(), 'replaced_by_payment_id': new_payment_record_id}}
                            )
                        
                        # Create a notice for the amount transfer
                        tab_data = get_current_tab_data()
                        admin_user_id = tab_data.get('user_id') if tab_data else None
                        
                        notice_data = {
                            'title': 'Amount Added Successfully',
                            'content': f'Your amount of ₹{amount_value} has been successfully transferred. New balance: ₹{new_amount}',
                            'author_id': admin_user_id,
                            'target_roles': ['admin'],
                            'priority': 'normal',
                            'created_at': datetime.utcnow(),
                            'updated_at': datetime.utcnow()
                        }
                        notices_collection.insert_one(notice_data)
                        
                        amount_flash_message = f' ₹{amount_value} has been added to your account!'
                except ValueError:
                    flash('Invalid amount format.', 'danger')
                    return redirect(url_for('payment_settings'))
        
        # Prepare update data - include the new amount and payment tracking
        payment_data = {
            'upi_id': upi_id,
            'upi_enabled': upi_enabled,
            'bank_name': bank_name,
            'account_number': account_number,
            'ifsc_code': ifsc_code,
            'account_holder_name': account_holder_name,
            'bank_transfer_enabled': bank_transfer_enabled,
            'qr_code': qr_code_path,
            'qr_code_enabled': qr_code_enabled,
            'amount': new_amount,
            'current_payment_id': new_payment_record_id if new_payment_record_id else existing_payment_id,
            'updated_at': datetime.utcnow()
        }
        # Update or insert payment settings
        if payment_settings:
            payment_settings_collection.update_one({'_id': payment_settings['_id']}, {'$set': payment_data})
        else:
            payment_data['created_at'] = datetime.utcnow()
            if new_payment_record_id:
                payment_data['current_payment_id'] = new_payment_record_id
            payment_settings_collection.insert_one(payment_data)
        
        # Flash appropriate message
        if amount_flash_message:
            flash(f'Your amount is successfully transfer!' + amount_flash_message, 'success')
        else:
            flash('Payment settings updated successfully!', 'success')
        
        return redirect(url_for('payment_settings'))
    
    return render_template('admin/payment_settings.html', payment_settings=payment_settings)

# Add Amount Route
@app.route('/admin/add-amount', methods=['POST'])
@role_required('admin')
def add_amount():
    amount = request.form.get('amount')
    
    if not amount:
        flash('Please enter an amount.', 'danger')
        return redirect(url_for('payment_settings'))
    
    try:
        amount = float(amount)
        if amount <= 0:
            flash('Amount must be greater than 0.', 'danger')
            return redirect(url_for('payment_settings'))
    except ValueError:
        flash('Invalid amount format.', 'danger')
        return redirect(url_for('payment_settings'))
    
    # Get payment settings to calculate new balance
    payment_settings = payment_settings_collection.find_one()
    
    # Get current balance
    current_amount = payment_settings.get('amount', 0) if payment_settings else 0
    existing_payment_id = payment_settings.get('current_payment_id') if payment_settings else None
    new_amount = current_amount + amount
    
    # Get version number
    last_payment = payments_collection.find_one(
        {'replaced_by_payment_id': {'$exists': False}},
        sort=[('version', -1)]
    )
    new_version = (last_payment.get('version', 0) + 1) if last_payment else 1
    
    # Update old payment to not be latest
    if existing_payment_id:
        payments_collection.update_one(
            {'_id': existing_payment_id},
            {'$set': {'is_latest': False, 'replaced_at': datetime.utcnow()}}
        )
    
    # Create a NEW payment record with version tracking
    payment_record = {
        'payment_number': f"PAY-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:8]}",
        'amount': amount,
        'balance_before': current_amount,
        'balance_after': new_amount,
        'payment_method': 'manual',
        'status': 'completed',
        'version': new_version,
        'previous_payment_id': existing_payment_id,
        'is_latest': True,
        'action_type': 'add',
        'created_at': datetime.utcnow(),
        'created_by': get_current_tab_data().get('user_id') if get_current_tab_data() else None
    }
    result = payments_collection.insert_one(payment_record)
    new_payment_record_id = result.inserted_id
    
    # Update old payment with reference to new payment
    if existing_payment_id:
        payments_collection.update_one(
            {'_id': existing_payment_id},
            {'$set': {'replaced_by_payment_id': new_payment_record_id}}
        )
    
    # Update the payment settings with new total amount and payment tracking
    if payment_settings:
        payment_settings_collection.update_one(
            {'_id': payment_settings['_id']},
            {'$set': {'amount': new_amount, 'current_payment_id': new_payment_record_id, 'updated_at': datetime.utcnow()}}
        )
    else:
        # Create new payment settings with amount if not exists
        payment_settings_collection.insert_one({
            'amount': new_amount,
            'current_payment_id': new_payment_record_id,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        })
    
    display_amount = new_amount
    
    # Create a notice/notification for the amount transfer
    tab_data = get_current_tab_data()
    admin_user_id = tab_data.get('user_id')
    
    notice_data = {
        'title': 'Amount Added Successfully',
        'content': f'Your amount of ₹{amount} has been successfully transferred. New balance: ₹{display_amount}',
        'author_id': admin_user_id,
        'target_roles': ['admin'],
        'priority': 'normal',
        'created_at': datetime.utcnow(),
        'updated_at': datetime.utcnow()
    }
    notices_collection.insert_one(notice_data)
    
    flash(f'Your amount is successfully transfer! ₹{amount} has been added to your account.', 'success')
    return redirect(url_for('payment_settings'))

@app.route('/admin/payments')
@role_required('admin')
def payment_history():
    # Get filter parameters
    payment_type = request.args.get('type', 'all')
    
    # Build query based on filter
    query = {}
    if payment_type == 'to_supplier':
        query['payment_type'] = 'to_supplier'
    elif payment_type == 'admin_balance':
        query['payment_type'] = {'$ne': 'to_supplier'}
    
    payments = list(payments_collection.find(query).sort('created_at', -1))
    
    # Enrich payments with supplier names for supplier payments
    for payment in payments:
        if payment.get('payment_type') == 'to_supplier' and payment.get('supplier_id'):
            try:
                supplier = users_collection.find_one({'_id': ObjectId(payment['supplier_id'])})
            except:
                supplier = users_collection.find_one({'_id': payment['supplier_id']})
            payment['supplier_name'] = supplier['company_name'] if supplier and supplier.get('company_name') else (supplier['username'] if supplier else 'Unknown')
        else:
            payment['supplier_name'] = None
    
    return render_template('admin/payment_history.html', payments=payments, payment_type=payment_type)

# Supplier Payments - Admin can pay suppliers
@app.route('/admin/supplier-payments', methods=['GET', 'POST'])
@role_required('admin')
def supplier_payments():
    if request.method == 'POST':
        # Handle AJAX request
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        
        supplier_id = request.form.get('supplier_id')
        amount = request.form.get('amount')
        payment_method = request.form.get('payment_method', 'upi')
        description = request.form.get('description', '')
        
        # Validate
        if not supplier_id:
            error_msg = 'Please select a supplier.'
            if is_ajax:
                return jsonify({'success': False, 'message': error_msg})
            flash(error_msg, 'danger')
            return redirect(url_for('supplier_payments'))
        
        if not amount:
            error_msg = 'Please enter an amount.'
            if is_ajax:
                return jsonify({'success': False, 'message': error_msg})
            flash(error_msg, 'danger')
            return redirect(url_for('supplier_payments'))
        
        try:
            amount = float(amount)
            if amount <= 0:
                error_msg = 'Amount must be greater than 0.'
                if is_ajax:
                    return jsonify({'success': False, 'message': error_msg})
                flash(error_msg, 'danger')
                return redirect(url_for('supplier_payments'))
        except ValueError:
            error_msg = 'Invalid amount format.'
            if is_ajax:
                return jsonify({'success': False, 'message': error_msg})
            flash(error_msg, 'danger')
            return redirect(url_for('supplier_payments'))
        
        # Get supplier details
        supplier = users_collection.find_one({'_id': ObjectId(supplier_id)})
        if not supplier:
            error_msg = 'Supplier not found.'
            if is_ajax:
                return jsonify({'success': False, 'message': error_msg})
            flash(error_msg, 'danger')
            return redirect(url_for('supplier_payments'))
        
        tab_data = get_current_tab_data()
        admin_user_id = tab_data.get('user_id') if tab_data else None
        admin_user = users_collection.find_one({'_id': ObjectId(admin_user_id)}) if admin_user_id else None
        admin_name = admin_user['username'] if admin_user else 'Admin'
        
        # Get admin's current balance from payment_settings
        payment_settings = payment_settings_collection.find_one()
        admin_balance = payment_settings.get('amount', 0) if payment_settings else 0
        
        # Check if admin has sufficient balance
        if admin_balance < amount:
            error_msg = f'Insufficient balance. Current balance: ₹{admin_balance}'
            if is_ajax:
                return jsonify({'success': False, 'message': error_msg})
            flash(error_msg, 'danger')
            return redirect(url_for('supplier_payments'))
        
        # Deduct from admin's balance
        new_admin_balance = admin_balance - amount

        # Get supplier's current wallet balance
        supplier_balance = supplier.get('wallet_balance', 0) if supplier else 0
        new_supplier_balance = supplier_balance + amount

        # Create payment record for supplier
        payment_record = {
            'payment_number': f"SUPPAY-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:8]}",
            'amount': amount,
            'balance_before': admin_balance,
            'balance_after': new_admin_balance,
            'payment_method': payment_method,
            'status': 'completed',
            'payment_type': 'to_supplier',
            'supplier_id': str(supplier_id),
            'supplier_name': supplier['company_name'] if supplier.get('company_name') else supplier['username'],
            'supplier_balance_before': supplier_balance,
            'supplier_balance_after': new_supplier_balance,
            'description': description,
            'created_at': datetime.utcnow(),
            'created_by': admin_user_id
        }
        payments_collection.insert_one(payment_record)

        # Update admin's balance in payment_settings
        if payment_settings:
            payment_settings_collection.update_one(
                {'_id': payment_settings['_id']},
                {'$set': {'amount': new_admin_balance, 'updated_at': datetime.utcnow()}}
            )
        else:
            payment_settings_collection.insert_one({
                'amount': new_admin_balance,
                'updated_at': datetime.utcnow()
            })

        # Update supplier's wallet balance
        users_collection.update_one(
            {'_id': ObjectId(supplier_id)},
            {'$set': {'wallet_balance': new_supplier_balance, 'wallet_updated_at': datetime.utcnow()}}
        )
        
        # Create notice
        notice_data = {
            'title': 'Payment Made to Supplier',
            'content': f'Admin {admin_name} made a payment of ₹{amount} to {supplier["company_name"] or supplier["username"]} via {payment_method.title()}. Remaining balance: ₹{new_admin_balance}',
            'author_id': admin_user_id,
            'target_roles': ['admin'],
            'priority': 'normal',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        notices_collection.insert_one(notice_data)
        
        success_msg = f'Payment of ₹{amount} made to {supplier["company_name"] or supplier["username"]} successfully!'
        
        if is_ajax:
            return jsonify({
                'success': True, 
                'message': success_msg,
                'new_balance': new_admin_balance
            })
        
        flash(success_msg, 'success')
        return redirect(url_for('supplier_payments'))
    
    # Get list of suppliers
    suppliers = list(users_collection.find({'role': 'supplier', 'is_active': True}))
    
    # Get recent supplier payments
    recent_payments = list(payments_collection.find(
        {'payment_type': 'to_supplier'}
    ).sort('created_at', -1).limit(5))
    
    # Enrich with supplier names
    for payment in recent_payments:
        if payment.get('supplier_id'):
            try:
                supplier = users_collection.find_one({'_id': ObjectId(payment['supplier_id'])})
            except:
                supplier = users_collection.find_one({'_id': payment['supplier_id']})
            payment['supplier_name'] = supplier['company_name'] if supplier and supplier.get('company_name') else (supplier['username'] if supplier else 'Unknown')
    
    # Get admin's current balance and payment settings
    payment_settings = payment_settings_collection.find_one()
    admin_balance = payment_settings.get('amount', 0) if payment_settings else 0

    return render_template('admin/supplier_payments.html', suppliers=suppliers, recent_payments=recent_payments, admin_balance=admin_balance, payment_settings=payment_settings)

# API to get admin balance
@app.route('/api/admin/balance')
@role_required('admin')
def api_admin_balance():
    payment_settings = payment_settings_collection.find_one()
    balance = payment_settings.get('amount', 0) if payment_settings else 0
    return jsonify({'balance': balance})

# API Endpoints for AJAX
@app.route('/api/products')
@login_required
def api_products():
    search = request.args.get('search', '')
    query = {}
    if search:
        query['name'] = {'$regex': search, '$options': 'i'}
    
    products = list(products_collection.find(query, {'_id': 1, 'name': 1, 'price': 1, 'stock': 1}).limit(20))
    for p in products:
        p['_id'] = str(p['_id'])
    
    return jsonify(products)

@app.route('/api/cart/count')
@role_required('manager')
def api_cart_count():
    tab_data = get_current_tab_data()
    user_id = tab_data.get('user_id')
    if not user_id:
        return jsonify({'count': 0})

    # Query cart items - handle both string and ObjectId formats
    # MongoDB will match both string and ObjectId if stored correctly
    # But we need to try both formats to be safe
    count = 0
    try:
        # First try with user_id as-is
        count = cart_collection.count_documents({'user_id': user_id})

        # If no results, try the other format
        if count == 0:
            if isinstance(user_id, str):
                # Try as ObjectId
                try:
                    user_id_obj = ObjectId(user_id)
                    count = cart_collection.count_documents({'user_id': user_id_obj})
                except:
                    pass
            else:
                # Try as string
                try:
                    user_id_str = str(user_id)
                    count = cart_collection.count_documents({'user_id': user_id_str})
                except:
                    pass
    except Exception as e:
        # If all else fails, return 0
        count = 0

    return jsonify({'count': count})

@app.route('/api/notifications/count')
@login_required
def api_notifications_count():
    tab_data = get_current_tab_data()
    active_role = tab_data.get('active_role') if tab_data else None
    if not active_role:
       return jsonify({'notices': 0, 'requests': 0, 'orders': 0})
    role = active_role
    user_id = tab_data.get('user_id')
    
    counts = {'notices': 0, 'requests': 0, 'orders': 0}
    
    # Count unread notices (simplified - could add read tracking)
    counts['notices'] = notices_collection.count_documents({
        '$or': [{'target_roles': {'$in': [role]}}, {'target_roles': {'$size': 0}}],
        'created_at': {'$gte': datetime.utcnow() - timedelta(days=7)}
    })
    
    if role == 'manager':
        counts['requests'] = requests_collection.count_documents({'manager_id': user_id, 'status': 'pending'})
    elif role == 'supplier':
        counts['orders'] = orders_collection.count_documents({'supplier_id': user_id, 'status': 'pending'})
    
    return jsonify(counts)

# Profile Management
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    tab_data = get_current_tab_data()
    active_role = tab_data.get('active_role') if tab_data else None
    user_id = tab_data.get('user_id')
    user_id_obj = safe_objectid(user_id)
    if not user_id_obj:
        flash('Invalid user session.', 'danger')
        return redirect(url_for('dashboard'))
    user = users_collection.find_one({'_id': user_id_obj})
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        update_data = {
            'username': request.form.get('username'),
        }
        
        if user['role'] == 'supplier':
            update_data['company_name'] = request.form.get('company_name', '')
            update_data['contact_number'] = request.form.get('contact_number', '')
            update_data['address'] = request.form.get('address', '')
        
        # Password change
        if request.form.get('new_password'):
            if check_password(request.form.get('current_password', ''), user['password']):
                update_data['password'] = hash_password(request.form.get('new_password'))
            else:
                flash('Current password is incorrect.', 'danger')
                return redirect(url_for('profile'))
        
        users_collection.update_one({'_id': ObjectId(user_id)}, {'$set': update_data})
        session['username'] = update_data['username']
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

@app.route('/profile/enable-2fa', methods=['POST'])
@login_required
def enable_2fa():
    """Enable Two-Factor Authentication"""
    tab_data = get_current_tab_data()
    active_role = tab_data.get('active_role') if tab_data else None
    user_id = tab_data.get('user_id')
    user_id_obj = safe_objectid(user_id)
    if not user_id_obj:
        flash('Invalid user session.', 'danger')
        return redirect(url_for('dashboard'))

    user = users_collection.find_one({'_id': user_id_obj})
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('dashboard'))
    
    email = user['email']
    
    # Send verification OTP
    otp = generate_otp(6)
    store_otp(email, otp, 'verification', expiry_minutes=10)
    
    if send_otp_email(email, otp, 'verification'):
        session['enable_2fa_pending'] = True
        flash('Please verify your email with the OTP sent to enable 2FA.', 'info')
        return redirect(url_for('verify_otp', email=email, purpose='verification'))
    else:
        flash('Error sending verification email.', 'danger')
        return redirect(url_for('profile'))

@app.route('/profile/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    """Disable Two-Factor Authentication"""
    active_role = session.get('active_role')
    user_id = session['users'][active_role]['user_id']
    user_id_obj = safe_objectid(user_id)
    if not user_id_obj:
        flash('Invalid user session.', 'danger')
        return redirect(url_for('dashboard'))
    
    users_collection.update_one(
        {'_id': user_id_obj},
        {'$set': {'two_factor_enabled': False}}
    )
    flash('Two-Factor Authentication has been disabled.', 'success')
    return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

# Supplier Customers View
@app.route('/supplier/customers')
@role_required('supplier')
def supplier_customers():
    tab_data = get_current_tab_data()
    user_id = tab_data.get('user_id')
    
    # Get unique managers who have ordered from this supplier
    pipeline = [
        {'$match': {'supplier_id': user_id}},
        {'$group': {'_id': '$manager_id', 'total_orders': {'$sum': 1}, 'total_spent': {'$sum': '$total'}}},
        {'$sort': {'total_spent': -1}}
    ]
    
    customer_stats = list(orders_collection.aggregate(pipeline))
    
    customers = []
    for stat in customer_stats:
        if stat.get('_id'):
            try:
                manager = users_collection.find_one({'_id': ObjectId(stat['_id'])})
            except:
                manager = users_collection.find_one({'_id': stat['_id']})
            if manager:
                customers.append({
                    'manager': manager,
                    'total_orders': stat['total_orders'],
                    'total_spent': stat['total_spent']
                })
    
    return render_template('supplier/customers.html', customers=customers)

# Supplier Payment History - View payments made to this supplier
@app.route('/supplier/payments')
@role_required('supplier')
def supplier_payment_history():
    tab_data = get_current_tab_data()
    user_id = tab_data.get('user_id')
    
    # Get all payments made to this supplier
    payments = list(payments_collection.find(
        {'supplier_id': user_id, 'payment_type': 'to_supplier'}
    ).sort('created_at', -1))
    
    # Calculate total payments received
    total_received = sum(p.get('amount', 0) for p in payments)
    
    return render_template('supplier/payments.html', payments=payments, total_received=total_received)

# Manager Staff Management
@app.route('/manager/staff')
@role_required('manager')
def manager_staff():
    tab_data = get_current_tab_data()
    active_role = tab_data.get('active_role') if tab_data else None
    user_id = tab_data.get('user_id')
    staff = list(users_collection.find({'role': 'staff', 'manager_id': user_id}))
    return render_template('manager/staff.html', staff=staff)

@app.route('/manager/suppliers')
@role_required('manager')
def manager_suppliers():
    suppliers = list(users_collection.find({'role': 'supplier'}))
    return render_template('manager/suppliers.html', suppliers=suppliers)

# Favicon route
@app.route('/favicon.ico')
def favicon():
    return '', 204  # No content

# Error Handlers
@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('errors/500.html'), 500

if __name__ == '__main__':
    # Create default admin user if not exists
    if not users_collection.find_one({'role': 'admin'}):
        users_collection.insert_one({
            'username': 'admin',
            'email': 'admin@example.com',
            'password': hash_password('admin123'),
            'role': 'admin',
            'created_at': datetime.utcnow(),
            'is_active': True
        })
        print("Default admin created: admin@example.com / admin123")
    
    # Use port 5001 to avoid Windows socket permission issues with port 5000
    app.run(debug=True, host='127.0.0.1', port=5001)

# ./app.py

from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, send_file, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt
from flask_pymongo import PyMongo
from bson import ObjectId
from pymongo import MongoClient
from flask_uploads import UploadSet, configure_uploads, IMAGES
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import json
import csv
import io
from collections import Counter
from flask_socketio import SocketIO, emit, join_room, leave_room

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Security Headers
from flask import request, g
from datetime import datetime

@app.after_request
def after_request(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)

# Secret key for session management
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
if not app.config['SECRET_KEY']:
    print("⚠️  SECRET_KEY not set in environment variables")
    print("📝 Please set SECRET_KEY in your .env file with a strong random value")
    exit(1)

# Database configuration
mongo_uri = os.getenv('MONGO_URI')
if mongo_uri:
    app.config["MONGO_URI"] = mongo_uri
    try:
        mongo = PyMongo(app)
        # Simple connection test - try to access database
        if mongo.db is not None:
            # Try to list collections as a simple connectivity test
            _ = list(mongo.db.list_collection_names())
            print("✅ MongoDB connection successful!")
        else:
            raise Exception("MongoDB client is None")
    except Exception as e:
        print(f"⚠️  MongoDB connection failed: {e}")
        print("📝 To fix this, install MongoDB or use MongoDB Atlas")
        print("   Local MongoDB: https://www.mongodb.com/try/download/community")
        print("   Or use MongoDB Atlas (cloud): https://www.mongodb.com/atlas")
        mongo = None
else:
    print("⚠️  MONGO_URI not set in environment variables")
    print("📝 Please set MONGO_URI in your .env file")
    mongo = None

# Upload configuration
app.config['UPLOADED_PHOTOS_DEST'] = os.getenv('UPLOAD_PATH', 'static/uploads')
# Create upload directory if it doesn't exist
import os
if not os.path.exists(app.config['UPLOADED_PHOTOS_DEST']):
    os.makedirs(app.config['UPLOADED_PHOTOS_DEST'])
    
photos = UploadSet('photos', IMAGES)
configure_uploads(app, photos)

# Mail configuration
mail_server = os.getenv('MAIL_SERVER')
mail_port = os.getenv('MAIL_PORT')
if mail_server and mail_port:
    app.config['MAIL_SERVER'] = mail_server
    app.config['MAIL_PORT'] = int(mail_port)
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
else:
    print("⚠️  Mail configuration not set in environment variables")
    print("📝 Please set MAIL_SERVER and MAIL_PORT in your .env file")
    # Set default values to prevent crashes
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = ''
    app.config['MAIL_PASSWORD'] = ''

mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def create_admin_user():
    # Admin user creation is now disabled to prevent hardcoded credentials
    # Admin users should be created through a secure setup process or registration
    print("Admin user creation through code is disabled for security reasons.")
    print("Admin users should be created via registration or secure setup process.")
    
    # Check if any admin user exists
    existing_admin = mongo.db.users.find_one({"role": "Admin"})
    if not existing_admin:
        print("⚠️  No admin user found. First user to register will become admin if allowed by configuration.")

# Define User model for authentication
class User(UserMixin):
    def __init__(self, user_dict):
        self.id = str(user_dict.get('_id'))
        self.username = user_dict.get('username')
        self.email = user_dict.get('email')
        self.password = user_dict.get('password')
        self.role = user_dict.get('role', 'User')
        self.alumni_id = user_dict.get('alumni_id')
        self.profile_picture = user_dict.get('profile_picture')
        self.created_at = user_dict.get('created_at')

    def is_admin(self):
        return self.role == 'Admin'

# Function to upgrade first user to admin if no admin exists
def upgrade_first_user_to_admin():
    """Upgrade the first registered user to admin if no admin exists"""
    if mongo is None:
        return
    
    # Check if any admin exists
    admin_exists = mongo.db.users.find_one({"role": "Admin"})
    
    if not admin_exists:
        # Get the first user sorted by creation date
        first_user = mongo.db.users.find_one({}, sort=[("created_at", 1)])
        if first_user:
            # Upgrade this user to admin
            mongo.db.users.update_one(
                {"_id": first_user['_id']},
                {"$set": {"role": "Admin"}}
            )
            print(f"First user {first_user['username']} upgraded to Admin") 

@login_manager.user_loader
def load_user(user_id):
    try:
        if mongo is None:
            return None
        user = mongo.db.users.find_one({"_id": ObjectId(user_id)})  # Convert to ObjectId
        # Logging user load for debugging
        app.logger.debug(f"Loading user with ID: {user_id}")
        if user:
            return User(user)
    except Exception as e:
        app.logger.error(f"Error loading user {user_id}: {str(e)}")
    return None

# Routes and view functions
@app.route('/')
def home():
    try:
        notifications = []
        upcoming_events = []
        recent_discussions = []
        job_posts = []
        mentorships = []
        
        if mongo is not None:
            notifications = list(mongo.db.notifications.find({}).sort("_id", -1).limit(5))
            upcoming_events = list(mongo.db.events.find({"date": {"$gte": datetime.today()}}).sort("date", 1).limit(5))
            recent_discussions = list(mongo.db.discussions.find().sort("_id", -1).limit(5))
            job_posts = list(mongo.db.job_posts.find().sort("_id", -1).limit(5))
            mentorships = list(mongo.db.mentorships.find().sort("_id", -1).limit(5))
        
        return render_template('home.html', datetime=datetime, upcoming_events=upcoming_events, 
                             recent_discussions=recent_discussions, notifications=notifications, 
                             job_posts=job_posts, mentorships=mentorships)
    except Exception as e:
        app.logger.error(f'Home page error: {str(e)}')
        return render_template('home.html', datetime=datetime, upcoming_events=[], 
                             recent_discussions=[], notifications=[], 
                             job_posts=[], mentorships=[])

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        notifications = []
        alumni = None
        upcoming_events = []
        recent_discussions = []
        user_jobs = []
        user_mentorships = []
        user_events = []
        
        if mongo is not None:
            notifications = list(mongo.db.notifications.find({
                "$or": [
                    {"recipients": "all"},
                    {"recipients": current_user.username}
                ]
            }).sort("created_at", -1))
            
            if current_user.alumni_id:
                alumni = mongo.db.alumni.find_one({"_id": ObjectId(current_user.alumni_id)})
            
            upcoming_events = list(mongo.db.events.find({"date": {"$gte": datetime.today()}}).sort("date", 1).limit(5))
            recent_discussions = list(mongo.db.discussions.find({"author": current_user.username}).sort("_id", -1).limit(5))
            user_jobs = list(mongo.db.job_posts.find({"posted_by": current_user.username}))
            user_mentorships = list(mongo.db.mentorships.find({"posted_by": current_user.username}))
            user_events = list(mongo.db.events.find({"posted_by": current_user.username}))
            user_discussions = list(mongo.db.discussions.find({"author": current_user.username}).sort("_id", -1).limit(5))
        
        return render_template('dashboard.html', notifications=notifications, user=current_user, 
                             alumni=alumni, upcoming_events=upcoming_events, 
                             recent_discussions=recent_discussions, user_jobs=user_jobs, 
                             user_mentorships=user_mentorships, user_events=user_events, 
                             user_discussions=user_discussions)
    except Exception as e:
        app.logger.error(f'Dashboard error: {str(e)}')
        flash('Error loading dashboard. Please try again.', 'danger')
        return render_template('dashboard.html', notifications=[], user=current_user, 
                             alumni=None, upcoming_events=[], recent_discussions=[], 
                             user_jobs=[], user_mentorships=[], user_events=[])

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def register():
    # Check rate limit
    if request.endpoint == 'register' and request.method == 'POST':
        if hasattr(request, 'is_rate_limited') and request.is_rate_limited:
            app.logger.warning(f"Rate limit exceeded for IP: {get_remote_address()}")
            flash('Too many registration attempts. Please try again later.', 'danger')
            return render_template('register.html')
    if mongo is None:
        flash('Database connection error. Please try again later.', 'danger')
        return render_template('register.html')
        
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')  # Add email field
            password = request.form.get('password')
            role = request.form.get('role', 'User')
            
            # Input validation
            if not username or len(username.strip()) < 3:
                flash('Username must be at least 3 characters long.', 'danger')
                return render_template('register.html')
            
            if not email or '@' not in email:
                flash('Please enter a valid email address.', 'danger')
                return render_template('register.html')
            
            if not password or len(password) < 6:
                flash('Password must be at least 6 characters long.', 'danger')
                return render_template('register.html')
            
            # Sanitize inputs
            username = username.strip()
            email = email.strip().lower()
            
            # Check if username or email already exists
            existing_user = mongo.db.users.find_one({"$or": [{"username": username}, {"email": email}]})
            if existing_user:
                if existing_user.get('username') == username:
                    flash('Username already exists. Please choose a different username.', 'danger')
                if existing_user.get('email') == email:
                    flash('Email already exists. Please use a different email.', 'danger')
                return render_template('register.html')
            
            # Hash password and create user
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            new_user = {
                "username": username, 
                "email": email,
                "password": hashed_password, 
                "role": role,
                "profile_picture": None,  # Will be added if uploaded
                "created_at": datetime.now()
            }
            
            # Handle profile picture upload
            if 'profile_picture' in request.files:
                file = request.files['profile_picture']
                if file and file.filename != '':
                    # Validate file type
                    if file.filename.rsplit('.', 1)[1].lower() in ['jpg', 'jpeg', 'png', 'gif']:
                        new_user["profile_picture"] = photos.save(file)
                    else:
                        flash('Invalid file type. Please upload an image file (jpg, jpeg, png, gif).', 'danger')
                        
            result = mongo.db.users.insert_one(new_user)
            app.logger.info(f"New user registered: {username} with ID: {result.inserted_id}")
            
            # Check if this should be the first admin user
            upgrade_first_user_to_admin()
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            flash(f'Registration failed: {str(e)}', 'danger')
            app.logger.error(f'Registration error: {str(e)}')
            return render_template('register.html')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    # Check rate limit
    if request.endpoint == 'login' and request.method == 'POST':
        if hasattr(request, 'is_rate_limited') and request.is_rate_limited:
            app.logger.warning(f"Rate limit exceeded for IP: {get_remote_address()}")
            flash('Too many login attempts. Please try again later.', 'danger')
            return render_template('login.html')
    if mongo is None:
        flash('Database connection error. Please try again later.', 'danger')
        return render_template('login.html')
        
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            
            # Input validation
            if not username or len(username.strip()) < 1:
                flash('Username is required.', 'danger')
                return render_template('login.html')
            
            if not password or len(password) < 1:
                flash('Password is required.', 'danger')
                return render_template('login.html')
            
            # Sanitize inputs
            username = username.strip()
            
            user = mongo.db.users.find_one({"username": username})
            
            # Log login attempt for debugging (without sensitive data)
            app.logger.info(f"Login attempt for username: {username}")
            
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
                app.logger.info(f"Successful login for user: {username}")
                user_obj = User(user)
                login_user(user_obj)
                
                flash(f'Welcome back, {username}!', 'success')
                
                if user_obj.is_admin():
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('dashboard'))
            else:
                flash('Login Unsuccessful. Please check username and password', 'danger')
                app.logger.warning(f"Failed login attempt for username: {username}")
        except Exception as e:
            flash(f'Login error: {str(e)}', 'danger')
            app.logger.error(f"Login error: {str(e)}")
    return render_template('login.html')

# Removed insecure emergency admin creation route
# This route posed a security risk with hardcoded credentials

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/update_password', methods=['GET', 'POST'])
@login_required
def update_password():
    if current_user.is_authenticated:
        user = mongo.db.users.find_one({'username':current_user.username})
        app.logger.debug(f"Loaded user data for: {current_user.username}")
        if request.method == 'POST':
            old_password = request.form['old_password']
            new_password = request.form['new_password']
            confirm_new_password = request.form['confirm_new_password']
            
            # Input validation
            if not old_password or len(old_password) < 1:
                flash('Old password is required.', 'danger')
                return render_template('change_password.html')
            
            if not new_password or len(new_password) < 6:
                flash('New password must be at least 6 characters long.', 'danger')
                return render_template('change_password.html')
            
            if new_password != confirm_new_password:
                flash('New password and confirmation do not match.', 'danger')
                return render_template('change_password.html')
            
            if bcrypt.checkpw(old_password.encode('utf-8'), user['password']):
                if bcrypt.checkpw(new_password.encode('utf-8'), user['password']):
                    flash('New password cannot be the same as the old password.', 'danger')
                    return render_template('change_password.html')

                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                mongo.db.users.update_one({"_id": user["_id"]}, {"$set": {"password":hashed_password}})
                app.logger.info(f"Password updated for user: {current_user.username}")
                flash('Password updated successfully!', 'success')
                return redirect(url_for('logout'))
            else:       
                flash('Old password is incorrect.', 'danger')
                return render_template('change_password.html')
        return render_template('change_password.html')
    else:
        return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('admin.html')

@app.route('/admin/profile', methods=['GET', 'POST'])
@login_required
def admin_profile():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        
        # Check if email already exists (excluding current user)
        existing_user = mongo.db.users.find_one({
            "email": email,
            "_id": {"$ne": ObjectId(current_user.id)}
        })
        if existing_user:
            flash('Email already exists. Please use a different email.', 'danger')
        else:
            mongo.db.users.update_one(
                {"_id": ObjectId(current_user.id)}, 
                {"$set": {"email": email}}
            )
            # Update current user object
            current_user.email = email
            flash('Email updated successfully!', 'success')
            return redirect(url_for('admin_profile'))
    
    # Get current admin user
    admin_user = mongo.db.users.find_one({"_id": ObjectId(current_user.id)})
    return render_template('admin_profile.html', user=admin_user)

@app.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
def admin_create_user():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'User')
        
        # Check if user already exists
        existing_user = mongo.db.users.find_one({"username": username})
        if existing_user:
            flash('Username already exists.', 'danger')
            return redirect(url_for('admin_create_user'))
            
        # Hash password and create user
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        new_user = {
            "username": username,
            "email": email,
            "password": hashed_password,
            "role": role,
            "created_at": datetime.now()
        }
        mongo.db.users.insert_one(new_user)
        flash('User created successfully!', 'success')
        return redirect(url_for('admin_manage_users'))
        
    return render_template('create_user.html')

@app.route('/admin/manage_users')
@login_required
def admin_manage_users():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    users = list(mongo.db.users.find())
    return render_template('manage_users.html', users=users)

@app.route('/admin/edit_user/<user_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_user(user_id):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_manage_users'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        role = request.form.get('role')
        
        # Update user
        mongo.db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {
                "username": username,
                "email": email,
                "role": role
            }}
        )
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin_manage_users'))
        
    return render_template('edit_user.html', user=user)

@app.route('/admin/delete_user/<user_id>')
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    # Prevent deleting the current user or admin user
    user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if user and user.get('username') == current_user.username:
        flash('You cannot delete yourself.', 'danger')
        return redirect(url_for('admin_manage_users'))
        
    mongo.db.users.delete_one({"_id": ObjectId(user_id)})
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_manage_users'))

# Profile routes
@app.route('/profile')
@login_required
def view_profile():
    alumni = None
    if current_user.alumni_id:
        alumni = mongo.db.alumni.find_one({"_id": ObjectId(current_user.alumni_id)})
    return render_template('profile.html', alumni=alumni)

@app.route('/create_profile', methods=['GET', 'POST'])
@login_required
def create_profile():
    if request.method == 'POST':
        name = request.form.get('name')
        bio = request.form.get('bio')
        graduation_year = request.form.get('graduation_year')
        industry = request.form.get('industry')
        contact_details = request.form.get('contact_details')
        
        # Create alumni profile
        alumni_profile = {
            "name": name,
            "bio": bio,
            "graduation_year": graduation_year,
            "industry": industry,
            "contact_details": contact_details,
            "created_by": current_user.username,
            "created_at": datetime.now()
        }
        
        result = mongo.db.alumni.insert_one(alumni_profile)
        
        # Update user with alumni_id
        mongo.db.users.update_one(
            {"_id": ObjectId(current_user.id)},
            {"$set": {"alumni_id": str(result.inserted_id)}}
        )
        
        flash('Profile created successfully!', 'success')
        return redirect(url_for('view_profile'))
        
    return render_template('create_profile.html')

@app.route('/edit_profile/<alumni_id>', methods=['GET', 'POST'])
@login_required
def edit_profile(alumni_id):
    alumni = mongo.db.alumni.find_one({"_id": ObjectId(alumni_id)})
    if not alumni:
        flash('Profile not found.', 'danger')
        return redirect(url_for('view_profile'))
        
    # Check if user owns this profile
    if str(alumni.get('_id')) != current_user.alumni_id:
        flash('You do not have permission to edit this profile.', 'danger')
        return redirect(url_for('view_profile'))
        
    if request.method == 'POST':
        # Check if this is a profile picture upload
        if 'photo' in request.files:
            file = request.files['photo']
            if file and file.filename != '':
                try:
                    # Save the profile picture
                    profile_picture = photos.save(file)
                    
                    # Update user with new profile picture
                    mongo.db.users.update_one(
                        {"_id": ObjectId(current_user.id)},
                        {"$set": {"profile_picture": profile_picture}}
                    )
                    
                    flash('Profile picture updated successfully!', 'success')
                    return redirect(url_for('view_profile'))
                except Exception as e:
                    flash(f'Error uploading profile picture: {str(e)}', 'danger')
                    return redirect(url_for('edit_profile', alumni_id=alumni_id))
        
        # Handle regular profile updates
        name = request.form.get('name')
        bio = request.form.get('bio')
        graduation_year = request.form.get('graduation_year')
        industry = request.form.get('industry')
        contact_details = request.form.get('contact_details')
        
        # Update alumni profile
        mongo.db.alumni.update_one(
            {"_id": ObjectId(alumni_id)},
            {"$set": {
                "name": name,
                "bio": bio,
                "graduation_year": graduation_year,
                "industry": industry,
                "contact_details": contact_details,
                "updated_at": datetime.now()
            }}
        )
        
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('view_profile'))
        
    return render_template('edit_profile.html', alumni=alumni)

# Event routes
@app.route('/events')
def list_events():
    events = list(mongo.db.events.find().sort("date", -1))
    return render_template('events.html', events=events)

@app.route('/events/<event_id>')
def view_event(event_id):
    event = mongo.db.events.find_one({"_id": ObjectId(event_id)})
    if not event:
        flash('Event not found.', 'danger')
        return redirect(url_for('list_events'))
    return render_template('view_event.html', event=event)

@app.route('/admin/create_event', methods=['GET', 'POST'])
@login_required
def admin_create_event():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        title = request.form.get('title')
        date_str = request.form.get('date')
        location = request.form.get('location')
        description = request.form.get('description')
        
        # Convert date string to datetime object
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d')
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD.', 'danger')
            return redirect(url_for('admin_create_event'))
        
        event = {
            "title": title,
            "date": date,
            "location": location,
            "description": description,
            "posted_by": current_user.username,
            "created_at": datetime.now()
        }
        
        mongo.db.events.insert_one(event)
        flash('Event created successfully!', 'success')
        return redirect(url_for('list_events'))
        
    return render_template('create_event.html')

@app.route('/admin/edit_event/<event_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_event(event_id):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    event = mongo.db.events.find_one({"_id": ObjectId(event_id)})
    if not event:
        flash('Event not found.', 'danger')
        return redirect(url_for('list_events'))
        
    if request.method == 'POST':
        title = request.form.get('title')
        date_str = request.form.get('date')
        location = request.form.get('location')
        description = request.form.get('description')
        
        # Convert date string to datetime object
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d')
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD.', 'danger')
            return redirect(url_for('admin_edit_event', event_id=event_id))
        
        mongo.db.events.update_one(
            {"_id": ObjectId(event_id)},
            {"$set": {
                "title": title,
                "date": date,
                "location": location,
                "description": description,
                "updated_at": datetime.now()
            }}
        )
        
        flash('Event updated successfully!', 'success')
        return redirect(url_for('view_event', event_id=event_id))
        
    return render_template('edit_event.html', event=event)

@app.route('/admin/delete_event/<event_id>')
@login_required
def admin_delete_event(event_id):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    event = mongo.db.events.find_one({"_id": ObjectId(event_id)})
    if not event:
        flash('Event not found.', 'danger')
        return redirect(url_for('list_events'))
        
    mongo.db.events.delete_one({"_id": ObjectId(event_id)})
    flash('Event deleted successfully!', 'success')
    return redirect(url_for('list_events'))

@app.route('/rsvp_event/<event_id>')
@login_required
def rsvp_event(event_id):
    event = mongo.db.events.find_one({"_id": ObjectId(event_id)})
    if not event:
        flash('Event not found.', 'danger')
        return redirect(url_for('list_events'))
    
    # Add user to the RSVP list for this event
    rsvp_data = {
        'event_id': event_id,
        'user_id': current_user.id,
        'username': current_user.username,
        'timestamp': datetime.now(),
        'status': 'confirmed'  # Default RSVP status
    }
    
    # Check if user has already RSVP'd
    existing_rsvp = mongo.db.event_rsvps.find_one({
        'event_id': event_id,
        'user_id': current_user.id
    })
    
    if existing_rsvp:
        # Update existing RSVP
        mongo.db.event_rsvps.update_one(
            {'_id': existing_rsvp['_id']},
            {'$set': {'status': 'confirmed', 'timestamp': datetime.now()}}
        )
        flash('Your RSVP has been updated!', 'success')
    else:
        # Create new RSVP
        mongo.db.event_rsvps.insert_one(rsvp_data)
        flash('You have successfully RSVP\'d to this event!', 'success')
    
    return redirect(url_for('view_event', event_id=event_id))

@app.route('/admin/delete_events', methods=['POST'])
@login_required
def admin_delete_events():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    
    event_ids = request.form.getlist('event_ids')
    if event_ids:
        # Convert string IDs to ObjectId and delete
        object_ids = [ObjectId(id_str) for id_str in event_ids]
        result = mongo.db.events.delete_many({"_id": {"$in": object_ids}})
        flash(f'{result.deleted_count} events deleted successfully!', 'success')
    else:
        flash('No events selected for deletion.', 'warning')
    
    return redirect(url_for('manage_events'))

# Discussion routes
@app.route('/discussions')
def list_discussions():
    discussions = list(mongo.db.discussions.find().sort("_id", -1))
    user_discussions = []
    if current_user.is_authenticated:
        user_discussions = list(mongo.db.discussions.find({"author": current_user.username}).sort("_id", -1).limit(5))
    return render_template('discussions.html', discussions=discussions, user_discussions=user_discussions)

@app.route('/discussions/<discussion_id>')
def view_discussion(discussion_id):
    discussion = mongo.db.discussions.find_one({"_id": ObjectId(discussion_id)})
    if not discussion:
        flash('Discussion not found.', 'danger')
        return redirect(url_for('list_discussions'))
        
    # Get replies
    replies = list(mongo.db.replies.find({"discussion_id": str(discussion_id)}).sort("_id", 1))
    return render_template('discussion.html', discussion=discussion, replies=replies)

@app.route('/admin/create_discussion', methods=['GET', 'POST'])
@login_required
def admin_create_discussion():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        topic = request.form.get('topic')
        content = request.form.get('content')
        category = request.form.get('category')
        
        discussion = {
            "topic": topic,
            "content": content,
            "author": current_user.username,
            "category": category,
            "created_at": datetime.now()
        }
        
        mongo.db.discussions.insert_one(discussion)
        flash('Discussion created successfully!', 'success')
        return redirect(url_for('list_discussions'))
        
    return render_template('create_discussion.html')

@app.route('/admin/edit_discussion/<discussion_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_discussion(discussion_id):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    discussion = mongo.db.discussions.find_one({"_id": ObjectId(discussion_id)})
    if not discussion:
        flash('Discussion not found.', 'danger')
        return redirect(url_for('list_discussions'))
        
    if request.method == 'POST':
        topic = request.form.get('topic')
        content = request.form.get('content')
        category = request.form.get('category')
        
        mongo.db.discussions.update_one(
            {"_id": ObjectId(discussion_id)},
            {"$set": {
                "topic": topic,
                "content": content,
                "category": category,
                "updated_at": datetime.now()
            }}
        )
        
        flash('Discussion updated successfully!', 'success')
        return redirect(url_for('view_discussion', discussion_id=discussion_id))
        
    return render_template('edit_discussion.html', discussion=discussion)

@app.route('/admin/delete_discussion/<discussion_id>')
@login_required
def admin_delete_discussion(discussion_id):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    discussion = mongo.db.discussions.find_one({"_id": ObjectId(discussion_id)})
    if not discussion:
        flash('Discussion not found.', 'danger')
        return redirect(url_for('list_discussions'))
        
    # Delete discussion and its replies
    mongo.db.discussions.delete_one({"_id": ObjectId(discussion_id)})
    mongo.db.replies.delete_many({"discussion_id": str(discussion_id)})
    
    flash('Discussion deleted successfully!', 'success')
    return redirect(url_for('list_discussions'))

@app.route('/admin/delete_discussions', methods=['POST'])
@login_required
def admin_delete_discussions():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    
    discussion_ids = request.form.getlist('discussion_ids')
    if discussion_ids:
        # Convert string IDs to ObjectId and delete discussions and their replies
        object_ids = [ObjectId(id_str) for id_str in discussion_ids]
        result = mongo.db.discussions.delete_many({"_id": {"$in": object_ids}})
        
        # Also delete all replies for these discussions
        for discussion_id in discussion_ids:
            mongo.db.replies.delete_many({"discussion_id": discussion_id})
        
        flash(f'{result.deleted_count} discussions deleted successfully!', 'success')
    else:
        flash('No discussions selected for deletion.', 'warning')
    
    return redirect(url_for('manage_discussions'))

@app.route('/discussions/<discussion_id>/reply', methods=['POST'])
@login_required
def add_reply(discussion_id):
    discussion = mongo.db.discussions.find_one({"_id": ObjectId(discussion_id)})
    if not discussion:
        flash('Discussion not found.', 'danger')
        return redirect(url_for('list_discussions'))
        
    content = request.form.get('content')
    if content:
        reply = {
            "content": content,
            "author": current_user.username,
            "discussion_id": str(discussion_id),
            "created_at": datetime.now()
        }
        mongo.db.replies.insert_one(reply)
        flash('Reply added successfully!', 'success')
    else:
        flash('Reply content cannot be empty.', 'danger')
        
    return redirect(url_for('view_discussion', discussion_id=discussion_id))

@app.route('/create_discussion', methods=['GET', 'POST'])
@login_required
def create_discussion():
    if request.method == 'POST':
        topic = request.form.get('topic')
        content = request.form.get('content')
        category = request.form.get('category')
        
        discussion = {
            "topic": topic,
            "content": content,
            "author": current_user.username,
            "category": category,
            "created_at": datetime.now()
        }
        
        mongo.db.discussions.insert_one(discussion)
        flash('Discussion created successfully!', 'success')
        return redirect(url_for('list_discussions'))
        
    return render_template('create_discussion.html')

@app.route('/edit_discussion/<discussion_id>', methods=['GET', 'POST'])
@login_required
def edit_discussion(discussion_id):
    discussion = mongo.db.discussions.find_one({"_id": ObjectId(discussion_id)})
    if not discussion:
        flash('Discussion not found.', 'danger')
        return redirect(url_for('list_discussions'))
    
    # Check if user owns this discussion
    if discussion.get('author') != current_user.username and not current_user.is_admin():
        flash('You do not have permission to edit this discussion.', 'danger')
        return redirect(url_for('list_discussions'))
    
    if request.method == 'POST':
        topic = request.form.get('topic')
        content = request.form.get('content')
        category = request.form.get('category')
        
        mongo.db.discussions.update_one(
            {"_id": ObjectId(discussion_id)},
            {"$set": {
                "topic": topic,
                "content": content,
                "category": category,
                "updated_at": datetime.now()
            }}
        )
        
        flash('Discussion updated successfully!', 'success')
        return redirect(url_for('view_discussion', discussion_id=discussion_id))
        
    return render_template('edit_discussion.html', discussion=discussion)

@app.route('/delete_discussion/<discussion_id>')
@login_required
def delete_discussion(discussion_id):
    discussion = mongo.db.discussions.find_one({"_id": ObjectId(discussion_id)})
    if not discussion:
        flash('Discussion not found.', 'danger')
        return redirect(url_for('list_discussions'))
    
    # Check if user owns this discussion or is admin
    if discussion.get('author') != current_user.username and not current_user.is_admin():
        flash('You do not have permission to delete this discussion.', 'danger')
        return redirect(url_for('list_discussions'))
    
    # Delete discussion and its replies
    mongo.db.discussions.delete_one({"_id": ObjectId(discussion_id)})
    mongo.db.replies.delete_many({"discussion_id": str(discussion_id)})
    
    flash('Discussion deleted successfully!', 'success')
    return redirect(url_for('list_discussions'))

# Job routes
@app.route('/jobs')
def list_jobs():
    jobs = list(mongo.db.job_posts.find().sort("_id", -1))
    return render_template('jobs.html', jobs=jobs)

@app.route('/jobs/<job_id>')
def view_job(job_id):
    job = mongo.db.job_posts.find_one({"_id": ObjectId(job_id)})
    if not job:
        flash('Job not found.', 'danger')
        return redirect(url_for('list_jobs'))
    return render_template('view_job.html', job=job)

@app.route('/admin/create_job', methods=['GET', 'POST'])
@login_required
def admin_create_job():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        company = request.form.get('company')
        location = request.form.get('location')
        
        job = {
            "title": title,
            "description": description,
            "company": company,
            "location": location,
            "posted_by": current_user.username,
            "created_at": datetime.now()
        }
        
        mongo.db.job_posts.insert_one(job)
        flash('Job posted successfully!', 'success')
        return redirect(url_for('list_jobs'))
        
    return render_template('create_job.html')

@app.route('/admin/edit_job/<job_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_job(job_id):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    job = mongo.db.job_posts.find_one({"_id": ObjectId(job_id)})
    if not job:
        flash('Job not found.', 'danger')
        return redirect(url_for('list_jobs'))
        
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        company = request.form.get('company')
        location = request.form.get('location')
        
        mongo.db.job_posts.update_one(
            {"_id": ObjectId(job_id)},
            {"$set": {
                "title": title,
                "description": description,
                "company": company,
                "location": location,
                "updated_at": datetime.now()
            }}
        )
        
        flash('Job updated successfully!', 'success')
        return redirect(url_for('view_job', job_id=job_id))
        
    return render_template('edit_job.html', job=job)

@app.route('/admin/delete_job/<job_id>')
@login_required
def admin_delete_job(job_id):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    job = mongo.db.job_posts.find_one({"_id": ObjectId(job_id)})
    if not job:
        flash('Job not found.', 'danger')
        return redirect(url_for('list_jobs'))
        
    mongo.db.job_posts.delete_one({"_id": ObjectId(job_id)})
    flash('Job deleted successfully!', 'success')
    return redirect(url_for('list_jobs'))

# Mentorship routes
@app.route('/mentorships')
def list_mentorships():
    mentorships = list(mongo.db.mentorships.find().sort("_id", -1))
    return render_template('mentorships.html', mentorships=mentorships)

@app.route('/mentorships/<mentorship_id>')
def view_mentorship(mentorship_id):
    mentorship = mongo.db.mentorships.find_one({"_id": ObjectId(mentorship_id)})
    if not mentorship:
        flash('Mentorship not found.', 'danger')
        return redirect(url_for('list_mentorships'))
    return render_template('view_mentorship.html', mentorship=mentorship)

@app.route('/admin/create_mentorship', methods=['GET', 'POST'])
@login_required
def admin_create_mentorship():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        mentor_name = request.form.get('mentor_name')
        mentee_name = request.form.get('mentee_name')
        details = request.form.get('details')
        contact_info = request.form.get('contact_info')
        
        mentorship = {
            "mentor_name": mentor_name,
            "mentee_name": mentee_name,
            "details": details,
            "contact_info": contact_info,
            "posted_by": current_user.username,
            "created_at": datetime.now()
        }
        
        mongo.db.mentorships.insert_one(mentorship)
        flash('Mentorship created successfully!', 'success')
        return redirect(url_for('list_mentorships'))
        
    return render_template('create_mentorship.html')

@app.route('/admin/edit_mentorship/<mentorship_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_mentorship(mentorship_id):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    mentorship = mongo.db.mentorships.find_one({"_id": ObjectId(mentorship_id)})
    if not mentorship:
        flash('Mentorship not found.', 'danger')
        return redirect(url_for('list_mentorships'))
        
    if request.method == 'POST':
        mentor_name = request.form.get('mentor_name')
        mentee_name = request.form.get('mentee_name')
        details = request.form.get('details')
        contact_info = request.form.get('contact_info')
        
        mongo.db.mentorships.update_one(
            {"_id": ObjectId(mentorship_id)},
            {"$set": {
                "mentor_name": mentor_name,
                "mentee_name": mentee_name,
                "details": details,
                "contact_info": contact_info,
                "updated_at": datetime.now()
            }}
        )
        
        flash('Mentorship updated successfully!', 'success')
        return redirect(url_for('view_mentorship', mentorship_id=mentorship_id))
        
    return render_template('edit_mentorship.html', mentorship=mentorship)

@app.route('/admin/delete_mentorship/<mentorship_id>')
@login_required
def admin_delete_mentorship(mentorship_id):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    mentorship = mongo.db.mentorships.find_one({"_id": ObjectId(mentorship_id)})
    if not mentorship:
        flash('Mentorship not found.', 'danger')
        return redirect(url_for('list_mentorships'))
        
    mongo.db.mentorships.delete_one({"_id": ObjectId(mentorship_id)})
    flash('Mentorship deleted successfully!', 'success')
    return redirect(url_for('list_mentorships'))

# Notification routes
@app.route('/admin/create_notification', methods=['GET', 'POST'])
@login_required
def admin_create_notification():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        message = request.form.get('message')
        recipients = request.form.getlist('recipients')
        
        notification = {
            "message": message,
            "recipients": recipients,
            "created_by": current_user.username,
            "created_at": datetime.now()
        }
        
        mongo.db.notifications.insert_one(notification)
        flash('Notification created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
        
    # Get all users for recipient selection
    users = list(mongo.db.users.find())
    return render_template('create_notification.html', users=users)

@app.route('/admin/manage_notifications')
@login_required
def admin_manage_notifications():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    notifications = list(mongo.db.notifications.find().sort("_id", -1))
    return render_template('manage_notifications.html', notifications=notifications)

@app.route('/admin/manage_events')
@login_required
def admin_manage_events():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    events = list(mongo.db.events.find().sort("date", -1))
    return render_template('manage_events.html', events=events)

@app.route('/admin/manage_jobs')
@login_required
def admin_manage_jobs():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    jobs = list(mongo.db.job_posts.find().sort("_id", -1))
    return render_template('manage_jobs.html', jobs=jobs)

@app.route('/admin/manage_discussions')
@login_required
def admin_manage_discussions():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    discussions = list(mongo.db.discussions.find().sort("_id", -1))
    return render_template('manage_discussions.html', discussions=discussions)

@app.route('/admin/edit_notification/<notification_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_notification(notification_id):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    notification = mongo.db.notifications.find_one({"_id": ObjectId(notification_id)})
    if not notification:
        flash('Notification not found.', 'danger')
        return redirect(url_for('admin_manage_notifications'))
        
    if request.method == 'POST':
        message = request.form.get('message')
        recipients = request.form.getlist('recipients')
        
        mongo.db.notifications.update_one(
            {"_id": ObjectId(notification_id)},
            {"$set": {
                "message": message,
                "recipients": recipients,
                "updated_at": datetime.now()
            }}
        )
        
        flash('Notification updated successfully!', 'success')
        return redirect(url_for('admin_manage_notifications'))
        
    # Get all users for recipient selection
    users = list(mongo.db.users.find())
    return render_template('edit_notification.html', notification=notification, users=users)

@app.route('/admin/delete_notification/<notification_id>')
@login_required
def admin_delete_notification(notification_id):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    notification = mongo.db.notifications.find_one({"_id": ObjectId(notification_id)})
    if not notification:
        flash('Notification not found.', 'danger')
        return redirect(url_for('admin_manage_notifications'))
        
    mongo.db.notifications.delete_one({"_id": ObjectId(notification_id)})
    flash('Notification deleted successfully!', 'success')
    return redirect(url_for('admin_manage_notifications'))

@app.route('/mark_as_read/<notification_id>')
@login_required
def mark_as_read(notification_id):
    notification = mongo.db.notifications.find_one({"_id": ObjectId(notification_id)})
    if notification:
        # Add current user to read_by list if not already there
        read_by = notification.get('read_by', [])
        if current_user.username not in read_by:
            read_by.append(current_user.username)
            mongo.db.notifications.update_one(
                {"_id": ObjectId(notification_id)},
                {"$set": {"read_by": read_by}}
            )
    return redirect(url_for('dashboard'))

# Add chat message deletion routes here, before SocketIO handlers
# Add this new route for deleting chat messages
@app.route('/admin/delete_chat_message/<message_id>', methods=['GET', 'POST'])
@login_required
def admin_delete_chat_message(message_id):
    """Delete a chat message (admin only)"""
    if not current_user.is_admin():
        flash('You do not have permission to delete chat messages.', 'danger')
        return redirect(url_for('chat'))
        
    if mongo is not None:
        try:
            result = mongo.db.chat_messages.delete_one({"_id": ObjectId(message_id)})
            if result.deleted_count > 0:
                flash('Message deleted successfully!', 'success')
            else:
                flash('Message not found.', 'danger')
        except Exception as e:
            flash(f'Error deleting message: {str(e)}', 'danger')
    
    return redirect(url_for('chat'))

# Add this new route for clearing all chat messages (admin only)
@app.route('/admin/clear_chat_history', methods=['GET', 'POST'])
@login_required
def admin_clear_chat_history():
    """Clear all chat messages (admin only)"""
    if not current_user.is_admin():
        flash('You do not have permission to clear chat history.', 'danger')
        return redirect(url_for('chat'))
        
    if mongo is not None:
        try:
            result = mongo.db.chat_messages.delete_many({})
            flash(f'Chat history cleared. {result.deleted_count} messages deleted.', 'success')
        except Exception as e:
            flash(f'Error clearing chat history: {str(e)}', 'danger')
    
    return redirect(url_for('chat'))

# Temporary route to clear chat data manually (for debugging purposes)
@app.route('/clear_chat_data_temp')
def clear_chat_data_temp():
    if mongo is not None:
        try:
            result = mongo.db.chat_messages.delete_many({})
            return f"Deleted {result.deleted_count} chat messages"
        except Exception as e:
            return f"Error: {str(e)}"
    return "MongoDB not connected"

# Post routes
@app.route('/posts')
def list_posts():
    posts = list(mongo.db.posts.find().sort("_id", -1))
    return render_template('posts.html', posts=posts)

@app.route('/posts/<post_id>')
def view_post(post_id):
    post = mongo.db.posts.find_one({"_id": ObjectId(post_id)})
    if not post:
        flash('Post not found.', 'danger')
        return redirect(url_for('list_posts'))
    return render_template('view_post.html', post=post)

@app.route('/user_posts/<username>')
@login_required
def user_posts(username):
    # Get the user object
    user = mongo.db.users.find_one({"username": username})
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('home'))
    
    # Get posts by the specific user
    posts = list(mongo.db.posts.find({"author": username}).sort("_id", -1))
    return render_template('user_posts.html', posts=posts, user=user)

@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        
        # Handle image upload
        image_filename = None
        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '':
                image_filename = photos.save(file)
        
        post = {
            "title": title,
            "content": content,
            "author": current_user.username,
            "image": image_filename,
            "created_at": datetime.now()
        }
        
        mongo.db.posts.insert_one(post)
        flash('Post created successfully!', 'success')
        return redirect(url_for('list_posts'))
        
    return render_template('create_post.html')

@app.route('/edit_post/<post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = mongo.db.posts.find_one({"_id": ObjectId(post_id)})
    if not post:
        flash('Post not found.', 'danger')
        return redirect(url_for('list_posts'))
        
    # Check if user owns this post
    if post.get('author') != current_user.username:
        flash('You do not have permission to edit this post.', 'danger')
        return redirect(url_for('list_posts'))
        
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        
        # Handle image upload
        update_data = {
            "title": title,
            "content": content,
            "updated_at": datetime.now()
        }
        
        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '':
                image_filename = photos.save(file)
                update_data["image"] = image_filename
        
        mongo.db.posts.update_one(
            {"_id": ObjectId(post_id)},
            {"$set": update_data}
        )
        
        flash('Post updated successfully!', 'success')
        return redirect(url_for('view_post', post_id=post_id))
        
    return render_template('edit_post.html', post=post)

@app.route('/delete_post/<post_id>')
@login_required
def delete_post(post_id):
    post = mongo.db.posts.find_one({"_id": ObjectId(post_id)})
    if not post:
        flash('Post not found.', 'danger')
        return redirect(url_for('list_posts'))
        
    # Check if user owns this post
    if post.get('author') != current_user.username:
        flash('You do not have permission to delete this post.', 'danger')
        return redirect(url_for('list_posts'))
        
    mongo.db.posts.delete_one({"_id": ObjectId(post_id)})
    flash('Post deleted successfully!', 'success')
    return redirect(url_for('user_posts'))

# Search functionality
@app.route('/search')
def global_search():
    query = request.args.get('q', '')
    if not query:
        return render_template('search_results.html', query=query, results=[])
        
    # Search across multiple collections
    events = list(mongo.db.events.find({"$text": {"$search": query}}))
    discussions = list(mongo.db.discussions.find({"$text": {"$search": query}}))
    jobs = list(mongo.db.job_posts.find({"$text": {"$search": query}}))
    mentorships = list(mongo.db.mentorships.find({"$text": {"$search": query}}))
    posts = list(mongo.db.posts.find({"$text": {"$search": query}}))
    
    results = {
        'events': events,
        'discussions': discussions,
        'jobs': jobs,
        'mentorships': mentorships,
        'posts': posts
    }
    
    return render_template('search_results.html', query=query, results=results)

# Analytics routes
@app.route('/admin/analytics')
@login_required
def analytics_dashboard():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    # Get statistics
    stats = {
        'total_users': mongo.db.users.count_documents({}),
        'total_events': mongo.db.events.count_documents({}),
        'total_discussions': mongo.db.discussions.count_documents({}),
        'total_jobs': mongo.db.job_posts.count_documents({}),
        'total_mentorships': mongo.db.mentorships.count_documents({}),
        'total_posts': mongo.db.posts.count_documents({})
    }
    
    # Get recent items
    recent_events = list(mongo.db.events.find().sort("_id", -1).limit(5))
    recent_discussions = list(mongo.db.discussions.find().sort("_id", -1).limit(5))
    recent_jobs = list(mongo.db.job_posts.find().sort("_id", -1).limit(5))
    
    stats['recent_events'] = recent_events
    stats['recent_discussions'] = recent_discussions
    stats['recent_jobs'] = recent_jobs
    
    # Get monthly statistics
    now = datetime.now()
    first_day = datetime(now.year, now.month, 1)
    
    monthly_stats = {
        'events_this_month': mongo.db.events.count_documents({"created_at": {"$gte": first_day}}),
        'discussions_this_month': mongo.db.discussions.count_documents({"created_at": {"$gte": first_day}}),
        'jobs_this_month': mongo.db.job_posts.count_documents({"created_at": {"$gte": first_day}}),
        'events_last_month': 0  # Simplified for now
    }
    
    return render_template('analytics.html', stats=stats, monthly_stats=monthly_stats)

# Data export routes
@app.route('/admin/export/<data_type>')
@login_required
def export_data(data_type):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
        
    # Define collections and fields based on data_type
    collections = {
        'users': (mongo.db.users, ['username', 'email', 'role', 'created_at']),
        'events': (mongo.db.events, ['title', 'date', 'location', 'description', 'posted_by', 'created_at']),
        'discussions': (mongo.db.discussions, ['topic', 'content', 'author', 'category', 'created_at']),
        'jobs': (mongo.db.job_posts, ['title', 'description', 'company', 'location', 'posted_by', 'created_at']),
        'mentorships': (mongo.db.mentorships, ['mentor_name', 'mentee_name', 'details', 'contact_info', 'posted_by', 'created_at'])
    }
    
    if data_type not in collections:
        flash('Invalid data type.', 'danger')
        return redirect(url_for('analytics_dashboard'))
        
    collection, fields = collections[data_type]
    data = list(collection.find())
    
    # Create CSV
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    
    for item in data:
        row = {}
        for field in fields:
            value = item.get(field, '')
            # Convert datetime objects to strings
            if isinstance(value, datetime):
                value = value.strftime('%Y-%m-%d %H:%M:%S')
            row[field] = value
        writer.writerow(row)
    
    # Return CSV file
    csv_data = output.getvalue()
    output.close()
    
    try:
        return Response(
            csv_data,
            mimetype='text/csv',
            headers={"Content-Disposition": f"attachment;filename={data_type}.csv"}
        )
    except Exception as e:
        app.logger.error(f'Export error: {str(e)}')
        flash('Error exporting data. Please try again.', 'danger')
        return redirect(url_for('analytics_dashboard'))

# Chat routes
@app.route('/chat')
@login_required
def chat():
    """Global chat room"""
    if mongo is None:
        flash('Database connection error. Please try again later.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get recent messages
    messages = list(mongo.db.chat_messages.find().sort('_id', -1).limit(50))
    messages.reverse()  # Show oldest first
    
    return render_template('chat.html', messages=messages)

@app.route('/messages')
@login_required
def messages():
    """Direct messages inbox"""
    if mongo is None:
        flash('Database connection error. Please try again later.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get conversations with other users
    conversations = mongo.db.direct_messages.aggregate([
        {
            '$match': {
                '$or': [
                    {'sender': current_user.username},
                    {'recipient': current_user.username}
                ]
            }
        },
        {
            '$sort': {'timestamp': -1}
        },
        {
            '$group': {
                '_id': {
                    '$cond': [
                        {'$eq': ['$sender', current_user.username]},
                        '$recipient',
                        '$sender'
                    ]
                },
                'last_message': {'$first': '$$ROOT'}
            }
        },
        {
            '$sort': {'last_message.timestamp': -1}
        }
    ])
    
    return render_template('messages.html', conversations=list(conversations))

@app.route('/messages/<username>')
@login_required
def conversation(username):
    """View conversation with a specific user"""
    if mongo is None:
        flash('Database connection error. Please try again later.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get messages between current user and specified user
    messages = list(mongo.db.direct_messages.find({
        '$or': [
            {'sender': current_user.username, 'recipient': username},
            {'sender': username, 'recipient': current_user.username}
        ]
    }).sort('timestamp', 1))
    
    # Mark messages as read
    mongo.db.direct_messages.update_many(
        {'sender': username, 'recipient': current_user.username, 'read': False},
        {'$set': {'read': True}}
    )
    
    return render_template('conversation.html', messages=messages, recipient=username)

# SocketIO event handlers
@socketio.on('join')
def handle_join(data):
    """Handle user joining a room"""
    username = data['username']
    room = data.get('room', 'global')
    
    join_room(room)
    
    # Update user status
    if mongo is not None:
        mongo.db.user_status.update_one(
            {'username': username},
            {'$set': {
                'status': 'online',
                'last_seen': datetime.now(),
                'room': room
            }},
            upsert=True
        )
    
    # Notify others in the room
    emit('user_joined', {
        'username': username,
        'message': f'{username} has joined the chat'
    }, room=room)

@socketio.on('leave')
def handle_leave(data):
    """Handle user leaving a room"""
    username = data['username']
    room = data.get('room', 'global')
    
    leave_room(room)
    
    # Update user status
    if mongo is not None:
        mongo.db.user_status.update_one(
            {'username': username},
            {'$set': {
                'status': 'offline',
                'last_seen': datetime.now()
            }}
        )
    
    # Notify others in the room
    emit('user_left', {
        'username': username,
        'message': f'{username} has left the chat'
    }, room=room)

@socketio.on('send_message')
def handle_send_message(data):
    """Handle sending a message"""
    username = data['username']
    message = data.get('message', '')
    room = data.get('room', 'global')
    file_data = data.get('file', None)
    
    # Save message to database
    if mongo is not None:
        message_doc = {
            'sender': username,
            'message': message,
            'timestamp': datetime.now(),
            'room': room
        }
        
        # Add file data if present
        if file_data:
            message_doc['file'] = {
                'name': file_data['name'],
                'type': file_data['type'],
                'data': file_data['data']  # This will be the base64 encoded file data
            }
        
        result = mongo.db.chat_messages.insert_one(message_doc)
        message_id = str(result.inserted_id)
    
    # Prepare broadcast data
    broadcast_data = {
        'username': username,
        'message': message,
        'timestamp': datetime.now().strftime('%H:%M'),
        'room': room,
        'message_id': message_id
    }
    
    # Add file data to broadcast if present
    if file_data:
        broadcast_data['file'] = {
            'name': file_data['name'],
            'type': file_data['type'],
            'data': file_data['data']
        }
    
    # Broadcast message to room
    emit('receive_message', broadcast_data, room=room)

@socketio.on('send_direct_message')
def handle_send_direct_message(data):
    """Handle sending a direct message"""
    sender = data['sender']
    recipient = data['recipient']
    message = data.get('message', '')
    file_data = data.get('file', None)
    
    # Save message to database
    if mongo is not None:
        message_doc = {
            'sender': sender,
            'recipient': recipient,
            'message': message,
            'timestamp': datetime.now(),
            'read': False
        }
        
        # Add file data if present
        if file_data:
            message_doc['file'] = {
                'name': file_data['name'],
                'type': file_data['type'],
                'data': file_data['data']  # This will be the base64 encoded file data
            }
        
        mongo.db.direct_messages.insert_one(message_doc)
    
    # Prepare emit data
    emit_data = {
        'sender': sender,
        'message': message,
        'timestamp': datetime.now().strftime('%H:%M')
    }
    
    # Add file data to emit if present
    if file_data:
        emit_data['file'] = {
            'name': file_data['name'],
            'type': file_data['type'],
            'data': file_data['data']
        }
    
    # Emit to recipient if online
    emit('receive_direct_message', emit_data, room=recipient)

@socketio.on('typing')
def handle_typing(data):
    """Handle typing indicator"""
    username = data['username']
    room = data.get('room', 'global')
    is_typing = data['typing']
    
    emit('user_typing', {
        'username': username,
        'typing': is_typing
    }, room=room, include_self=False)

@socketio.on('disconnect')
def handle_disconnect():
    """Handle user disconnecting"""
    # Update user status to offline
    if mongo is not None:
        # We don't have the username here, so we'll need to handle this differently
        pass

@app.route('/admin/logo-upload')
@login_required
def admin_logo_upload():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('logo_upload.html')

@app.route('/admin/logo-analytics')
@login_required
def admin_logo_analytics():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('logo_analytics.html')

@app.route('/logo-demo')
@login_required
def logo_demo():
    return render_template('logo_demo.html')

if __name__ == '__main__':
    create_admin_user()
    # Check and upgrade first user to admin if needed
    upgrade_first_user_to_admin()
    app.secret_key = os.urandom(24)
    # Suppress the development server warning
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    # Run with use_reloader=False to avoid Windows socket issues
    socketio.run(app, debug=True, use_reloader=False)

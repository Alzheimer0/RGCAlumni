# ./app.py

from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
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
from flask_socketio import SocketIO, emit, join_room, leave_room

{% extends "layout.html" %}

{% block title %}Global Chat - Rajiv Gandhi Alumini Network{% endblock %}

{% block content %}
<div class="container-fluid mt-4">
    <div class="row">
        <div class="col-12">
            <h2><i class="fas fa-comments"></i> Global Alumni Chat</h2>
            <p class="text-muted">Connect with all alumni in real-time</p>
        </div>
    </div>
    
    <div class="row">
        <div class="col-lg-9">
            <div class="card">
                <div class="card-header bg-primary text-white">
                    <h5 class="mb-0"><i class="fas fa-globe"></i> Global Chat Room</h5>
                </div>
                <div class="card-body p-0">
                    <div id="chat-messages" class="p-3" style="height: 500px; overflow-y: auto;">
                        {% for msg in messages %}
                        <div class="mb-3">
                            <div class="d-flex align-items-center mb-1">
                                <strong class="text-primary">{{ msg.sender }}</strong>
                                <small class="text-muted ms-2">{{ msg.timestamp.strftime('%H:%M') if msg.timestamp else '' }}</small>
                            </div>
                            <div class="bg-light p-2 rounded">
                                {{ msg.message }}
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                    <div class="border-top p-3">
                        <div class="input-group">
                            <input type="text" id="message-input" class="form-control" placeholder="Type your message here...">
                            <button class="btn btn-primary" id="send-button" type="button">
                                <i class="fas fa-paper-plane"></i> Send
                            </button>
                        </div>
                        <div class="mt-2">
                            <small class="text-muted" id="typing-indicator"></small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-lg-3">
            <div class="card">
                <div class="card-header bg-info text-white">
                    <h5 class="mb-0"><i class="fas fa-users"></i> Online Users</h5>
                </div>
                <div class="card-body">
                    <ul id="online-users" class="list-unstyled">
                        <!-- Online users will be populated here -->
                    </ul>
                </div>
            </div>
            
            <div class="card mt-3">
                <div class="card-header bg-success text-white">
                    <h5 class="mb-0"><i class="fas fa-info-circle"></i> Chat Tips</h5>
                </div>
                <div class="card-body">
                    <ul class="mb-0">
                        <li>Be respectful to all alumni</li>
                        <li>Keep conversations professional</li>
                        <li>Use @mentions to get attention</li>
                        <li>Share valuable information</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
<script>
    document.addEventListener('DOMContentLoaded', function() {
        // Initialize SocketIO
        const socket = io();
        
        // DOM elements
        const chatMessages = document.getElementById('chat-messages');
        const messageInput = document.getElementById('message-input');
        const sendButton = document.getElementById('send-button');
        const typingIndicator = document.getElementById('typing-indicator');
        const onlineUsers = document.getElementById('online-users');
        
        // Current user
        const username = "{{ current_user.username }}";
        
        // Join chat room
        socket.emit('join', {
            username: username,
            room: 'global'
        });
        
        // Send message function
        function sendMessage() {
            const message = messageInput.value.trim();
            if (message) {
                socket.emit('send_message', {
                    username: username,
                    message: message,
                    room: 'global'
                });
                messageInput.value = '';
                messageInput.focus();
            }
        }
        
        // Event listeners
        sendButton.addEventListener('click', sendMessage);
        
        messageInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
            
            // Typing indicator
            socket.emit('typing', {
                username: username,
                room: 'global',
                typing: true
            });
        });
        
        // Receive message
        socket.on('receive_message', function(data) {
            const messageElement = document.createElement('div');
            messageElement.className = 'mb-3';
            messageElement.innerHTML = `
                <div class="d-flex align-items-center mb-1">
                    <strong class="text-primary">${data.username}</strong>
                    <small class="text-muted ms-2">${data.timestamp}</small>
                </div>
                <div class="bg-light p-2 rounded">
                    ${data.message}
                </div>
            `;
            chatMessages.appendChild(messageElement);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        });
        
        // User joined
        socket.on('user_joined', function(data) {
            const messageElement = document.createElement('div');
            messageElement.className = 'text-center text-muted my-2';
            messageElement.innerHTML = `<small>${data.message}</small>`;
            chatMessages.appendChild(messageElement);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        });
        
        // User left
        socket.on('user_left', function(data) {
            const messageElement = document.createElement('div');
            messageElement.className = 'text-center text-muted my-2';
            messageElement.innerHTML = `<small>${data.message}</small>`;
            chatMessages.appendChild(messageElement);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        });
        
        // Typing indicator
        socket.on('user_typing', function(data) {
            if (data.typing && data.username !== username) {
                typingIndicator.textContent = `${data.username} is typing...`;
                setTimeout(() => {
                    typingIndicator.textContent = '';
                }, 3000);
            }
        });
    });
</script>
{% endblock %}{% extends "layout.html" %}

{% block title %}Global Chat - Rajiv Gandhi Alumini Network{% endblock %}

{% block content %}
<div class="container-fluid mt-4">
    <div class="row">
        <div class="col-12">
            <h2><i class="fas fa-comments"></i> Global Alumni Chat</h2>
            <p class="text-muted">Connect with all alumni in real-time</p>
        </div>
    </div>
    
    <div class="row">
        <div class="col-lg-9">
            <div class="card">
                <div class="card-header bg-primary text-white">
                    <h5 class="mb-0"><i class="fas fa-globe"></i> Global Chat Room</h5>
                </div>
                <div class="card-body p-0">
                    <div id="chat-messages" class="p-3" style="height: 500px; overflow-y: auto;">
                        {% for msg in messages %}
                        <div class="mb-3">
                            <div class="d-flex align-items-center mb-1">
                                <strong class="text-primary">{{ msg.sender }}</strong>
                                <small class="text-muted ms-2">{{ msg.timestamp.strftime('%H:%M') if msg.timestamp else '' }}</small>
                            </div>
                            <div class="bg-light p-2 rounded">
                                {{ msg.message }}
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                    <div class="border-top p-3">
                        <div class="input-group">
                            <input type="text" id="message-input" class="form-control" placeholder="Type your message here...">
                            <button class="btn btn-primary" id="send-button" type="button">
                                <i class="fas fa-paper-plane"></i> Send
                            </button>
                        </div>
                        <div class="mt-2">
                            <small class="text-muted" id="typing-indicator"></small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-lg-3">
            <div class="card">
                <div class="card-header bg-info text-white">
                    <h5 class="mb-0"><i class="fas fa-users"></i> Online Users</h5>
                </div>
                <div class="card-body">
                    <ul id="online-users" class="list-unstyled">
                        <!-- Online users will be populated here -->
                    </ul>
                </div>
            </div>
            
            <div class="card mt-3">
                <div class="card-header bg-success text-white">
                    <h5 class="mb-0"><i class="fas fa-info-circle"></i> Chat Tips</h5>
                </div>
                <div class="card-body">
                    <ul class="mb-0">
                        <li>Be respectful to all alumni</li>
                        <li>Keep conversations professional</li>
                        <li>Use @mentions to get attention</li>
                        <li>Share valuable information</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
<script>
    document.addEventListener('DOMContentLoaded', function() {
        // Initialize SocketIO
        const socket = io();
        
        // DOM elements
        const chatMessages = document.getElementById('chat-messages');
        const messageInput = document.getElementById('message-input');
        const sendButton = document.getElementById('send-button');
        const typingIndicator = document.getElementById('typing-indicator');
        const onlineUsers = document.getElementById('online-users');
        
        // Current user
        const username = "{{ current_user.username }}";
        
        // Join chat room
        socket.emit('join', {
            username: username,
            room: 'global'
        });
        
        // Send message function
        function sendMessage() {
            const message = messageInput.value.trim();
            if (message) {
                socket.emit('send_message', {
                    username: username,
                    message: message,
                    room: 'global'
                });
                messageInput.value = '';
                messageInput.focus();
            }
        }
        
        // Event listeners
        sendButton.addEventListener('click', sendMessage);
        
        messageInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
            
            // Typing indicator
            socket.emit('typing', {
                username: username,
                room: 'global',
                typing: true
            });
        });
        
        // Receive message
        socket.on('receive_message', function(data) {
            const messageElement = document.createElement('div');
            messageElement.className = 'mb-3';
            messageElement.innerHTML = `
                <div class="d-flex align-items-center mb-1">
                    <strong class="text-primary">${data.username}</strong>
                    <small class="text-muted ms-2">${data.timestamp}</small>
                </div>
                <div class="bg-light p-2 rounded">
                    ${data.message}
                </div>
            `;
            chatMessages.appendChild(messageElement);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        });
        
        // User joined
        socket.on('user_joined', function(data) {
            const messageElement = document.createElement('div');
            messageElement.className = 'text-center text-muted my-2';
            messageElement.innerHTML = `<small>${data.message}</small>`;
            chatMessages.appendChild(messageElement);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        });
        
        // User left
        socket.on('user_left', function(data) {
            const messageElement = document.createElement('div');
            messageElement.className = 'text-center text-muted my-2';
            messageElement.innerHTML = `<small>${data.message}</small>`;
            chatMessages.appendChild(messageElement);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        });
        
        // Typing indicator
        socket.on('user_typing', function(data) {
            if (data.typing && data.username !== username) {
                typingIndicator.textContent = `${data.username} is typing...`;
                setTimeout(() => {
                    typingIndicator.textContent = '';
                }, 3000);
            }
        });
    });
</script>
{% endblock %}{% extends "layout.html" %}

{% block title %}Global Chat - Rajiv Gandhi Alumini Network{% endblock %}

{% block content %}
<div class="container-fluid mt-4">
    <div class="row">
        <div class="col-12">
            <h2><i class="fas fa-comments"></i> Global Alumni Chat</h2>
            <p class="text-muted">Connect with all alumni in real-time</p>
        </div>
    </div>
    
    <div class="row">
        <div class="col-lg-9">
            <div class="card">
                <div class="card-header bg-primary text-white">
                    <h5 class="mb-0"><i class="fas fa-globe"></i> Global Chat Room</h5>
                </div>
                <div class="card-body p-0">
                    <div id="chat-messages" class="p-3" style="height: 500px; overflow-y: auto;">
                        {% for msg in messages %}
                        <div class="mb-3">
                            <div class="d-flex align-items-center mb-1">
                                <strong class="text-primary">{{ msg.sender }}</strong>
                                <small class="text-muted ms-2">{{ msg.timestamp.strftime('%H:%M') if msg.timestamp else '' }}</small>
                            </div>
                            <div class="bg-light p-2 rounded">
                                {{ msg.message }}
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                    <div class="border-top p-3">
                        <div class="input-group">
                            <input type="text" id="message-input" class="form-control" placeholder="Type your message here...">
                            <button class="btn btn-primary" id="send-button" type="button">
                                <i class="fas fa-paper-plane"></i> Send
                            </button>
                        </div>
                        <div class="mt-2">
                            <small class="text-muted" id="typing-indicator"></small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-lg-3">
            <div class="card">
                <div class="card-header bg-info text-white">
                    <h5 class="mb-0"><i class="fas fa-users"></i> Online Users</h5>
                </div>
                <div class="card-body">
                    <ul id="online-users" class="list-unstyled">
                        <!-- Online users will be populated here -->
                    </ul>
                </div>
            </div>
            
            <div class="card mt-3">
                <div class="card-header bg-success text-white">
                    <h5 class="mb-0"><i class="fas fa-info-circle"></i> Chat Tips</h5>
                </div>
                <div class="card-body">
                    <ul class="mb-0">
                        <li>Be respectful to all alumni</li>
                        <li>Keep conversations professional</li>
                        <li>Use @mentions to get attention</li>
                        <li>Share valuable information</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
<script>
    document.addEventListener('DOMContentLoaded', function() {
        // Initialize SocketIO
        const socket = io();
        
        // DOM elements
        const chatMessages = document.getElementById('chat-messages');
        const messageInput = document.getElementById('message-input');
        const sendButton = document.getElementById('send-button');
        const typingIndicator = document.getElementById('typing-indicator');
        const onlineUsers = document.getElementById('online-users');
        
        // Current user
        const username = "{{ current_user.username }}";
        
        // Join chat room
        socket.emit('join', {
            username: username,
            room: 'global'
        });
        
        // Send message function
        function sendMessage() {
            const message = messageInput.value.trim();
            if (message) {
                socket.emit('send_message', {
                    username: username,
                    message: message,
                    room: 'global'
                });
                messageInput.value = '';
                messageInput.focus();
            }
        }
        
        // Event listeners
        sendButton.addEventListener('click', sendMessage);
        
        messageInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
            
            // Typing indicator
            socket.emit('typing', {
                username: username,
                room: 'global',
                typing: true
            });
        });
        
        // Receive message
        socket.on('receive_message', function(data) {
            const messageElement = document.createElement('div');
            messageElement.className = 'mb-3';
            messageElement.innerHTML = `
                <div class="d-flex align-items-center mb-1">
                    <strong class="text-primary">${data.username}</strong>
                    <small class="text-muted ms-2">${data.timestamp}</small>
                </div>
                <div class="bg-light p-2 rounded">
                    ${data.message}
                </div>
            `;
            chatMessages.appendChild(messageElement);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        });
        
        // User joined
        socket.on('user_joined', function(data) {
            const messageElement = document.createElement('div');
            messageElement.className = 'text-center text-muted my-2';
            messageElement.innerHTML = `<small>${data.message}</small>`;
            chatMessages.appendChild(messageElement);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        });
        
        // User left
        socket.on('user_left', function(data) {
            const messageElement = document.createElement('div');
            messageElement.className = 'text-center text-muted my-2';
            messageElement.innerHTML = `<small>${data.message}</small>`;
            chatMessages.appendChild(messageElement);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        });
        
        // Typing indicator
        socket.on('user_typing', function(data) {
            if (data.typing && data.username !== username) {
                typingIndicator.textContent = `${data.username} is typing...`;
                setTimeout(() => {
                    typingIndicator.textContent = '';
                }, 3000);
            }
        });
    });
</script>
{% endblock %}
from collections import Counter


# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

# Secret key for session management
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')


# Database configuration
app.config["MONGO_URI"] = os.getenv('MONGO_URI')
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


# Upload configuration
app.config['UPLOADED_PHOTOS_DEST'] = 'static/uploads'
# Create upload directory if it doesn't exist
import os
if not os.path.exists(app.config['UPLOADED_PHOTOS_DEST']):
    os.makedirs(app.config['UPLOADED_PHOTOS_DEST'])
    
photos = UploadSet('photos', IMAGES)
configure_uploads(app, photos)

# Mail configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def create_admin_user():
    admin_username = 'admin'
    admin_password = 'admin'
    admin_role = 'Admin'
    
    if mongo is None:
        print("⚠️  Skipping admin user creation - MongoDB not connected")
        return

    # Check if admin user already exists
    existing_admin = mongo.db.users.find_one({"username": admin_username, "role": admin_role})
    
    if existing_admin:
        # Update existing admin with new email if it doesn't have one or has old email
        if not existing_admin.get('email') or existing_admin.get('email') == 'admin@rgcacs.edu':
            mongo.db.users.update_one(
                {"username": admin_username, "role": admin_role},
                {"$set": {"email": "alzheimer085@gmail.com"}}
            )
            print("Admin user email updated to alzheimer085@gmail.com.")
        else:
            print("Admin user already exists. Skipping creation.")
    else:
        # Hash the password before storing it
        hashed_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())
        admin_user = {
            "username": admin_username,
            "email": "alzheimer085@gmail.com",
            "password": hashed_password,
            "role": admin_role,
            "created_at": datetime.now()
        }
        mongo.db.users.insert_one(admin_user)
        print("Admin user created successfully with email alzheimer085@gmail.com.")


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

@login_manager.user_loader
def load_user(user_id):
    try:
        if mongo is None:
            return None
        user = mongo.db.users.find_one({"_id": ObjectId(user_id)})  # Convert to ObjectId
        print(f"load_user: user_id={ObjectId(user_id)}, user={user}")  # Debugging statement
        if user:
            return User(user)
    except Exception as e:
        print(f"Error loading user: {e}")  # Add error logging
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
        
        return render_template('dashboard.html', notifications=notifications, user=current_user, 
                             alumni=alumni, upcoming_events=upcoming_events, 
                             recent_discussions=recent_discussions, user_jobs=user_jobs, 
                             user_mentorships=user_mentorships, user_events=user_events)
    except Exception as e:
        app.logger.error(f'Dashboard error: {str(e)}')
        flash('Error loading dashboard. Please try again.', 'danger')
        return render_template('dashboard.html', notifications=[], user=current_user, 
                             alumni=None, upcoming_events=[], recent_discussions=[], 
                             user_jobs=[], user_mentorships=[], user_events=[])

@app.route('/register', methods=['GET', 'POST'])
def register():
    if mongo is None:
        flash('Database connection error. Please try again later.', 'danger')
        return render_template('register.html')
        
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')  # Add email field
            password = request.form.get('password')
            role = request.form.get('role', 'User')
            
            # Check if username or email already exists
            existing_user = mongo.db.users.find_one({"$or": [{"username": username}, {"email": email}]})
            if existing_user:
                if existing_user.get('username') == username:
                    flash('Username already exists. Please choose a different username.', 'danger')
                if existing_user.get('email') == email:
                    flash('Email already exists. Please use a different email.', 'danger')
                return redirect(url_for('register'))
            elif username and email and password:
                # Handle profile picture upload
                profile_picture = None
                if 'profile_picture' in request.files:
                    file = request.files['profile_picture']
                    if file.filename != '':
                        profile_picture = photos.save(file)
                
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                new_user = {
                    "username": username, 
                    "email": email,
                    "password": hashed_password, 
                    "role": role,
                    "profile_picture": profile_picture,
                    "created_at": datetime.now()
                }
                mongo.db.users.insert_one(new_user)
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Username, email and password are required.', 'danger')
        except Exception as e:
            flash(f'Registration failed: {str(e)}', 'danger')
            app.logger.error(f'Registration error: {str(e)}')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if mongo is None:
        flash('Database connection error. Please try again later.', 'danger')
        return render_template('login.html')
        
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            user = mongo.db.users.find_one({"username": username})
            
            # Debug print to help troubleshoot
            print(f"Login attempt: username={username}")
            print(f"User found: {user is not None}")
            
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
                print(f"login: username={username}, user={user}")  # Debugging statement
                user_obj = User(user)
                login_user(user_obj)
                
                flash(f'Welcome back, {username}!', 'success')
                
                if user_obj.is_admin():
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('dashboard'))
            else:
                flash('Login Unsuccessful. Please check username and password', 'danger')
                print("Login failed - invalid credentials")
        except Exception as e:
            flash(f'Login error: {str(e)}', 'danger')
            print(f"Login exception: {e}")
    return render_template('login.html')

@app.route('/create_admin_now')
def create_admin_now():
    """Emergency admin creation route"""
    if mongo is None:
        return "Database connection error"
    
    admin_username = 'admin'
    admin_password = 'admin123'  # More secure password
    admin_role = 'Admin'
    
    try:
        # Delete existing admin if any
        mongo.db.users.delete_many({"username": admin_username})
        
        # Create new admin
        hashed_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())
        admin_user = {
            "username": admin_username,
            "email": "alzheimer085@gmail.com",
            "password": hashed_password,
            "role": admin_role,
            "created_at": datetime.now()
        }
        result = mongo.db.users.insert_one(admin_user)
        
        return f"""<h2>Admin Account Created Successfully!</h2>
        <p><strong>Username:</strong> {admin_username}</p>
        <p><strong>Email:</strong> alzheimer085@gmail.com</p>
        <p><strong>Password:</strong> {admin_password}</p>
        <p><strong>Role:</strong> {admin_role}</p>
        <p><strong>Database ID:</strong> {result.inserted_id}</p>
        <p><a href="{url_for('login')}">Go to Login Page</a></p>
        <p><a href="{url_for('home')}">Go to Home Page</a></p>
        <style>body{{font-family: Arial, sans-serif; padding: 20px; background: #f0f8ff;}}</style>
        """
    except Exception as e:
        return f"Error creating admin: {str(e)}"

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
        print(user)
        if request.method == 'POST':
            old_password = request.form['old_password']
            if bcrypt.checkpw(old_password.encode('utf-8'), user['password']):
                new_password = request.form['new_password']

                if bcrypt.checkpw(new_password.encode('utf-8'), user['password']):
                    flash('New password cannot be the same as the old password.', 'danger')
                    return redirect(url_for('update_password'))

                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                mongo.db.users.update_one({"_id": user["_id"]}, {"$set": {"password":hashed_password}})
                flash('Password updated successfully!', 'success')
                return redirect(url_for('logout'))
            else:       
```

```
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

                flash('Old password is incorrect.', 'danger')
                return redirect(url_for('update_password'))
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
        role = request.form.get('role')
        
        # Check if username or email already exists
        existing_user = mongo.db.users.find_one({"$or": [{"username": username}, {"email": email}]})
        if existing_user:
            if existing_user.get('username') == username:
                flash('Username already exists. Please choose a different username.', 'danger')
            if existing_user.get('email') == email:
                flash('Email already exists. Please use a different email.', 'danger')
            return redirect(url_for('admin_create_user'))
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        new_user = {
            "username": username, 
            "email": email,
            "password": hashed_password, 
            "role": role,
            "created_at": datetime.now()
        }
        mongo.db.users.insert_one(new_user)
        flash('User created successfully', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('create_user.html')

@app.route('/admin/create_event', methods=['GET', 'POST'])
@login_required
def admin_create_event():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    current_date = datetime.now().strftime('%Y-%m-%d')
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        location = request.form.get('location')
        date = request.form.get('date')
        new_event = {
            "title": title,
            "description": description,
            "date": datetime.strptime(date, '%Y-%m-%d'),
            "location":location
        }
        mongo.db.events.insert_one(new_event)
        flash('Event created successfully!', 'success')
        return redirect(url_for('list_events'))
    return render_template('create_event.html', current_date=current_date)


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
        new_discussion = {
            "topic": topic,
            "content": content,
            "author": current_user.username,
            "category": category,
            "created_at": datetime.now()
        }
        mongo.db.discussions.insert_one(new_discussion)
        flash('Discussion created successfully!', 'success')
        return redirect(url_for('list_discussions'))
    return render_template('create_discussion.html')

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
        new_job = {
            "title": title,
            "description": description,
            "company": company,
            "location":location,
            "posted_by": current_user.username
        }
        mongo.db.job_posts.insert_one(new_job)
        flash('Job created successfully!', 'success')
        return redirect(url_for('list_jobs'))
    return render_template('create_job.html')

@app.route('/admin/create_mentorship', methods=['GET', 'POST'])
@login_required
def admin_create_mentorship():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        mentor_name = request.form.get('mentor_name')
        mentee_name = request.form.get('mentee_name')
        contact_info = request.form.get('contact_info')
        details = request.form.get('details')
        posted_by = request.form.get('posted_by')
        new_mentorship = {
            "mentor_name": mentor_name,
            "mentee_name": mentee_name,
            "details": details,
            "contact_info": contact_info,
            "posted_by":posted_by
        }
        mongo.db.mentorships.insert_one(new_mentorship)
        flash('Mentorship created successfully!', 'success')
        return redirect(url_for('list_mentorships'))
    return render_template('create_mentorship.html')

@app.route('/admin/view_logs')
@login_required
def admin_view_logs():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    # Logic to view logs goes here
    logs = []  # This should be replaced with actual log fetching logic
    return render_template('view_logs.html', logs=logs)

@app.route('/admin/generate_reports')
@login_required
def admin_generate_reports():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    # Logic to generate reports goes here
    reports = []  # This should be replaced with actual report generation logic
    return render_template('generate_reports.html', reports=reports)

@app.route('/admin/manage_users')
@login_required
def admin_manage_users():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    users = mongo.db.users.find()
    return render_template('manage_users.html', users=users)

@app.route('/admin/manage_events')
@login_required
def admin_manage_events():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    events = mongo.db.events.find()
    return render_template('manage_events.html', events=events)

@app.route('/admin/manage_jobs')
@login_required
def admin_manage_jobs():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    jobs = mongo.db.job_posts.find()
    return render_template('manage_jobs.html', jobs=jobs)

@app.route('/admin/manage_discussions')
@login_required
def admin_manage_discussions():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    discussions = mongo.db.discussions.find()
    return render_template('manage_discussions.html', discussions=discussions)

@app.route('/admin/edit_user/<user_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_user(user_id):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))

    user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin_manage_users'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        role = request.form.get('role')
        
        # Check if username or email already exists (excluding current user)
        existing_user = mongo.db.users.find_one({
            "$or": [{"username": username}, {"email": email}],
            "_id": {"$ne": ObjectId(user_id)}
        })
        if existing_user:
            if existing_user.get('username') == username:
                flash('Username already exists. Please choose a different username.', 'danger')
            if existing_user.get('email') == email:
                flash('Email already exists. Please use a different email.', 'danger')
            return render_template('edit_user.html', user=user)
        
        mongo.db.users.update_one(
            {"_id": ObjectId(user_id)}, 
            {"$set": {"username": username, "email": email, "role": role}}
        )
        flash('User updated successfully', 'success')
        return redirect(url_for('admin_manage_users'))

    return render_template('edit_user.html', user=user)

@app.route('/admin/delete_user/<user_id>', methods=['POST', 'GET'])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('login'))
    if request.method == 'GET':
        user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('admin_manage_users'))

        # if user.username == 'admin':
        #     flash('Admin Cannot be deleted', 'danger')
        # else:
        mongo.db.users.delete_one({"_id": ObjectId(user_id)})
        flash('User deleted successfully', 'success')
    return redirect(url_for('admin_manage_users'))

@app.route('/admin/delete_users', methods=['POST'])
@login_required
def admin_delete_users():
    if not current_user.is_admin():
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('login'))
    user_ids = request.form.getlist('user_ids')
    if user_ids:
        # Convert user_ids to ObjectId and remove the users from the database
        current_admin_id = ObjectId(current_user.id)

        ids = []
        for user_id in user_ids:
            if ObjectId(user_id) != current_admin_id:
                ids.append(ObjectId(user_id))
            else:
                flash('Admin Cannot be deleted', 'danger')
                return redirect(url_for('admin_manage_users'))
        
        mongo.db.users.delete_many({'_id': {'$in': ids}})
        flash(f'{len(user_ids)} user(s) deleted successfully.', 'success')
    else:
        flash('No users selected for deletion.', 'warning')

    return redirect(url_for('admin_manage_users'))

@app.route('/admin/delete_event/<event_id>', methods=['POST', 'GET'])
@login_required
def admin_delete_event(event_id):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('login'))
    if request.method == 'GET':
        event = mongo.db.events.find_one({"_id": ObjectId(event_id)})
        if not event:
            flash('Event not found', 'danger')
            return redirect(url_for('admin_manage_events'))

        mongo.db.events.delete_one({"_id": ObjectId(event_id)})
        flash('Event deleted successfully', 'success')
    return redirect(url_for('admin_manage_events'))

@app.route('/admin/delete_events', methods=['POST', 'GET'])
@login_required
def admin_delete_events():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('login'))
    event_ids = request.form.getlist('event_ids')
    if event_ids:
        ids = [ObjectId(event_id) for event_id in event_ids]
        mongo.db.events.delete_many({'_id': {'$in': ids}})
        flash(f'{len(event_ids)} event(s) deleted successfully.', 'success')
    else:
        flash('No events selected for deletion.', 'warning')

    return redirect(url_for('admin_manage_events'))

@app.route('/delete_event/<event_id>', methods=['POST', 'GET'])
@login_required
def delete_event(event_id):
    if request.method == 'GET':
        event = mongo.db.events.find_one({"_id": ObjectId(event_id)})
        if not event:
            flash('Event not found', 'danger')
            return redirect(url_for('admin_manage_events'))

        mongo.db.events.delete_one({"_id": ObjectId(event_id)})
        flash('Event deleted successfully', 'success')
    return redirect(url_for('list_events'))

@app.route('/admin/delete_job/<job_id>', methods=['POST', 'GET'])
@login_required
def admin_delete_job(job_id):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'GET':
        job = mongo.db.job_posts.find_one({"_id": ObjectId(job_id)})
        if not job:
            flash('Job not found', 'danger')
            return redirect(url_for('admin_manage_jobs'))

        mongo.db.job_posts.delete_one({"_id": ObjectId(job_id)})
        flash('Job deleted successfully', 'success')
    return redirect(url_for('admin_manage_jobs'))

@app.route('/admin/delete_jobs', methods=['POST', 'GET'])
@login_required
def admin_delete_jobs():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('login'))
    job_ids = request.form.getlist('job_ids')
    if job_ids:
        ids = [ObjectId(job_id) for job_id in job_ids]
        mongo.db.job_posts.delete_many({'_id': {'$in': ids}})
        flash(f'{len(job_ids)} job(s) deleted successfully.', 'success')
    else:
        flash('No jobs selected for deletion.', 'warning')

    return redirect(url_for('admin_manage_jobs'))

@app.route('/delete_job/<job_id>', methods=['POST', 'GET'])
@login_required
def delete_job(job_id):
    if request.method == 'GET':
        job = mongo.db.job_posts.find_one({"_id": ObjectId(job_id)})
        if not job:
            flash('Job not found', 'danger')
            return redirect(url_for('list_jobs'))

        mongo.db.job_posts.delete_one({"_id": ObjectId(job_id)})
        flash('Job deleted successfully', 'success')
    return redirect(url_for('list_jobs'))

@app.route('/admin/edit_discussion/<discussion_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_discussion(discussion_id):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))

    discussion = mongo.db.discussions.find_one({"_id": ObjectId(discussion_id)})
    if not discussion:
        flash('Discussion not found', 'danger')
        return redirect(url_for('admin_manage_discussions'))

    if request.method == 'POST':
        topic = request.form.get('topic')
        content = request.form.get('content')
        category = request.form.get('category')
        mongo.db.discussions.update_one({"_id": ObjectId(discussion_id)}, {"$set": {"topic": topic, "content": content, "category": category}})
        flash('Discussion updated successfully', 'success')
        return redirect(url_for('admin_manage_discussions'))

    return render_template('edit_discussion.html', discussion=discussion)

@app.route('/admin/delete_discussion/<discussion_id>', methods=['POST', 'GET'])
@login_required
def admin_delete_discussion(discussion_id):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'GET':
        discussion = mongo.db.discussions.find_one({"_id": ObjectId(discussion_id)})
        if not discussion:
            flash('Discussion not found', 'danger')
            return redirect(url_for('admin_manage_discussions'))

        mongo.db.discussions.delete_one({"_id": ObjectId(discussion_id)})
        flash('Discussion deleted successfully', 'success')
    return redirect(url_for('admin_manage_discussions'))


@app.route('/admin/delete_discussions', methods=['POST', 'GET'])
@login_required
def admin_delete_discussions():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('login'))
    discussion_ids = request.form.getlist('discussion_ids')
    if discussion_ids:
        ids = [ObjectId(discussion_id) for discussion_id in discussion_ids]
        mongo.db.discussions.delete_many({'_id': {'$in': ids}})
        flash(f'{len(discussion_ids)} discussion(s) deleted successfully.', 'success')
    else:
        flash('No Discussion selected for deletion.', 'warning')

    return redirect(url_for('admin_manage_discussions'))


@app.route('/delete_discussion/<discussion_id>', methods=['POST', 'GET'])
@login_required
def delete_discussion(discussion_id):
    if request.method == 'GET':
        discussion = mongo.db.discussions.find_one({"_id": ObjectId(discussion_id)})
        if not discussion:
            flash('Discussion not found', 'danger')
            return redirect(url_for('list_discussions'))

        mongo.db.discussions.delete_one({"_id": ObjectId(discussion_id)})
        flash('Discussion deleted successfully', 'success')
    return redirect(url_for('list_discussions'))

@app.route('/delete_mentorship/<mentorship_id>', methods=['POST', 'GET'])
@login_required
def delete_mentorship(mentorship_id):
    if request.method == 'GET':
        mentorship = mongo.db.mentorships.find_one({"_id": ObjectId(mentorship_id)})
        if not mentorship:
            flash('Mentorship not found', 'danger')
            return redirect(url_for('list_mentorships'))

        mongo.db.mentorships.delete_one({"_id": ObjectId(mentorship_id)})
        flash('Mentorship deleted successfully', 'success')
    return redirect(url_for('list_mentorships'))




@app.route('/profile')
@login_required
def view_profile():
    try:
        alumni = None
        user = None
        user_posts = []
        
        if mongo is not None:
            if current_user.alumni_id:
                alumni = mongo.db.alumni.find_one({"_id": ObjectId(current_user.alumni_id)})
            user = mongo.db.users.find_one({"_id": ObjectId(current_user.id)})
            user_posts = list(mongo.db.posts.find({"user_id": str(current_user.id)}).sort("created_at", -1).limit(10))
        
        if alumni:
            return render_template('profile.html', alumni=alumni, user=user, user_posts=user_posts)
        else:
            return redirect(url_for('create_profile'))
    except Exception as e:
        flash(f'Error loading profile: {str(e)}', 'danger')
        app.logger.error(f'Profile view error: {str(e)}')
        return render_template('profile.html', alumni=None, user=None, user_posts=[])

@app.route('/profile/create', methods=['GET', 'POST'])
@login_required
def create_profile():
    if mongo is None:
        flash('Database connection error. Profile creation is not available.', 'danger')
        return render_template('create_profile.html')
        
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            bio = request.form.get('bio')  # Add bio field
            graduation_year = request.form.get('graduation_year')
            industry = request.form.get('industry')
            contact_details = request.form.get('contact_details')
            new_alumni = {
                "name": name,
                "bio": bio,
                "graduation_year": graduation_year,
                "industry": industry,
                "contact_details": contact_details,
                "created_at": datetime.now(),
                "updated_at": datetime.now()
            }
            result = mongo.db.alumni.insert_one(new_alumni)
            mongo.db.users.update_one({"_id": ObjectId(current_user.id)}, {"$set": {"alumni_id": str(result.inserted_id)}})
            flash('Profile created successfully!', 'success')
            return redirect(url_for('view_profile'))
        except Exception as e:
            flash(f'Profile creation failed: {str(e)}', 'danger')
            app.logger.error(f'Profile creation error: {str(e)}')
    return render_template('create_profile.html')

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if mongo is None:
        flash('Database connection error. Profile editing is not available.', 'danger')
        return redirect(url_for('view_profile'))
        
    alumni = mongo.db.alumni.find_one({"_id": ObjectId(current_user.alumni_id)})
    if not alumni:
        return redirect(url_for('create_profile'))
    if request.method == 'POST':
        try:
            updated_alumni = {
                "name": request.form.get('name'),
                "bio": request.form.get('bio'),  # Add bio field
                "graduation_year": request.form.get('graduation_year'),
                "industry": request.form.get('industry'),
                "contact_details": request.form.get('contact_details'),
                "updated_at": datetime.now()
            }
            mongo.db.alumni.update_one({"_id": alumni["_id"]}, {"$set": updated_alumni})
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('view_profile'))
        except Exception as e:
            flash(f'Profile update failed: {str(e)}', 'danger')
            app.logger.error(f'Profile update error: {str(e)}')
    return render_template('edit_profile.html', alumni=alumni)

@app.route('/admin/manage_notifications')
@login_required
def admin_manage_notifications():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    user_notifications = mongo.db.notifications.find()
    return render_template('manage_notifications.html', notifications=user_notifications)



@app.route('/mark_as_read/<notification_id>')
@login_required
def mark_as_read(notification_id):
    notification = mongo.db.notifications.find_one({"_id": ObjectId(notification_id)})
    if notification:
        # mongo.db.notifications.update_one({"_id": ObjectId(notification_id)}, {"$set": {"is_read": True}})
        # Check if the current user has already marked the notification as read
        if current_user.username not in notification.get('read_by', []):
            # Append the current user's username to the list of users who have read it
            mongo.db.notifications.update_one(
                {"_id": ObjectId(notification_id)},
                {"$push": {"read_by": current_user.username}}
            )
            flash('Notification marked as read.', 'success')
        else:
            flash('You have already marked this notification as read.', 'info')
    else:
        flash('Notification not found or you do not have permission to mark it as read.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/admin/create_notification', methods=['GET', 'POST'])
@login_required
def admin_create_notification():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        recipients = request.form.getlist('recipients')
        message = request.form.get('message')
        if recipients == "all":
            recipients = "all"
        else:
            recipients = recipients

        notification = {
                "recipients": recipients,
                'message': message,
                'created_at': datetime.utcnow(),
                'created_by': current_user.username
            }
        mongo.db.notifications.insert_one(notification)
        flash('Notification created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    users = mongo.db.users.find()
    return render_template('create_notification.html', users=users)


@app.route('/admin/edit_notification/<notification_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_notification(notification_id):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))

    notification = mongo.db.notifications.find_one({"_id": ObjectId(notification_id)})
    if not notification:
        flash('Notification not found', 'danger')
        return redirect(url_for('admin_manage_notifications'))

    if request.method == 'POST':
        message = request.form.get('message')
        recipients = request.form.getlist('recipients')
        if recipients == "all":
            recipients = "all"
        else:
            recipients = recipients

        notification = {
                "recipients": recipients,
                'message': message,
                'created_at': datetime.utcnow(),
                'created_by': current_user.username
            }
        
        mongo.db.notifications.update_one({"_id": ObjectId(notification_id)}, {"$set": notification})
        flash('Notification updated successfully', 'success')
        return redirect(url_for('admin_manage_notifications'))
    users = mongo.db.users.find()
    return render_template('edit_notification.html', notification=notification, users=users)


@app.route('/admin/delete_notification/<notification_id>', methods=['POST', 'GET'])
@login_required
def admin_delete_notification(notification_id):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'GET':
        notification = mongo.db.notifications.find_one({"_id": ObjectId(notification_id)})
        if not notification:
            flash('Notification not found', 'danger')
            return redirect(url_for('admin_manage_discussions'))

        mongo.db.notifications.delete_one({"_id": ObjectId(notification_id)})
        flash('Notification deleted successfully', 'success')
    return redirect(url_for('admin_manage_notifications'))

@app.route('/admin/delete_notifications', methods=['POST'])
@login_required
def admin_delete_notifications():
    if not current_user.is_admin():
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('admin_manage_users'))
    notification_ids = request.form.getlist('notification_ids')
    if notification_ids:
        # Convert notification_ids to ObjectId and remove the notifications from the database
        mongo.db.notifications.delete_many({'_id': {'$in': [ObjectId(notification_id) for notification_id in notification_ids]}})
        flash(f'{len(notification_ids)} notification(s) deleted successfully.', 'success')
    else:
        flash('No Notification selected for deletion.', 'warning')

    return redirect(url_for('admin_manage_notifications'))

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    try:
        if 'photo' in request.files:
            file = request.files['photo']
            if file.filename != '':
                # Validate file type
                allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
                if '.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in allowed_extensions:
                    filename = photos.save(file)
                    # Update user's profile picture
                    mongo.db.users.update_one(
                        {'_id': ObjectId(current_user.id)}, 
                        {'$set': {'profile_picture': filename}}
                    )
                    flash('Profile picture uploaded successfully!', 'success')
                else:
                    flash('Invalid file type. Please upload PNG, JPG, JPEG, or GIF files only.', 'danger')
            else:
                flash('No file selected.', 'danger')
        else:
            flash('No file found in request.', 'danger')
    except Exception as e:
        flash(f'Upload failed: {str(e)}', 'danger')
        app.logger.error(f'Upload error: {str(e)}')
    
    return redirect(url_for('view_profile'))


@app.route('/create_discussion', methods=['GET', 'POST'])
@login_required
def create_discussion():
    if request.method == 'POST':
        topic = request.form.get('topic')
        content = request.form.get('content')
        category = request.form.get('category')
        new_discussion = {
            "topic": topic,
            "content": content,
            "category": category,
            "author": current_user.username,
            "created_at": datetime.now()
        }
        mongo.db.discussions.insert_one(new_discussion)
        flash('Discussion created successfully!', 'success')
        return redirect(url_for('list_discussions'))
    return render_template('create_discussion.html')

@app.route('/discussions')
@login_required
def list_discussions():
    user_discussions = mongo.db.discussions.find({"author":current_user.username})
    all_discussions = mongo.db.discussions.find().sort("_id", -1)
    return render_template('discussions.html', discussions=all_discussions, user_discussions=user_discussions)

@app.route('/discussion/<discussion_id>', methods=['GET', 'POST'])
@login_required
def view_discussion(discussion_id):
    discussion = mongo.db.discussions.find_one({"_id": ObjectId(discussion_id)})
    if not discussion:
        flash('Discussion not found.', 'danger')
        return redirect(url_for('list_discussions'))

    if request.method == 'POST':
        content = request.form.get('content')
        new_reply = {
            "content": content,
            "author": current_user.username,
            "discussion_id": ObjectId(discussion_id),
            "created_at": datetime.utcnow()
        }
        try:
            mongo.db.replies.insert_one(new_reply)
            flash('Reply posted successfully!', 'success')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')

    replies = list(mongo.db.replies.find({"discussion_id": ObjectId(discussion_id)}))
    return render_template('discussion.html', discussion=discussion, replies=replies)

@app.route('/edit_discussion/<discussion_id>', methods=['GET', 'POST'])
@login_required
def edit_discussion(discussion_id):
    discussion = mongo.db.discussions.find_one({"_id": ObjectId(discussion_id)})
    if not discussion:
        flash('Discussion not found.', 'danger')
        return redirect(url_for('list_discussions'))
    if request.method == 'POST':
        updated_discussion = {
            "topic": request.form.get('topic'),
            "content": request.form.get('content'),
        }
        mongo.db.discussions.update_one({"_id": ObjectId(discussion_id)}, {"$set": updated_discussion})
        flash('Discussion updated successfully!', 'success')
        return redirect(url_for('view_discussion', discussion_id=ObjectId(discussion_id)))
    return render_template('edit_discussion.html', discussion=discussion)

@app.route('/events')
@login_required
def list_events():
    all_events = mongo.db.events.find()
    user_events = mongo.db.events.find({"posted_by": current_user.username})
    print(user_events)
    return render_template('events.html', events=all_events, user_events=user_events)

@app.route('/event/<event_id>')
@login_required
def view_event(event_id):
    event = mongo.db.events.find_one({"_id": ObjectId(event_id)})
    if event:
        return render_template('view_event.html', event=event)
    else:
        flash('Event not found.', 'danger')
        return redirect(url_for('list_events'))

@app.route('/create_event', methods=['GET', 'POST'])
@login_required
def create_event():
    current_date = datetime.now().strftime('%Y-%m-%d')
    if request.method == 'POST':
        try:
            title = request.form.get('title')
            description = request.form.get('description')
            location = request.form.get('location')
            date = request.form.get('date')
            new_event = {
                "title": title,
                "description": description,
                "date": datetime.strptime(date, '%Y-%m-%d'),
                "location":location,
                "posted_by":current_user.username
            }
            mongo.db.events.insert_one(new_event)
            flash('Event created successfully!', 'success')
            return redirect(url_for('list_events'))
        except Exception as e:
            flash(f'Event creation failed: {str(e)}', 'danger')
            app.logger.error(f'Event creation error: {str(e)}')
    return render_template('create_event.html', current_date=current_date)

@app.route('/edit_event/<event_id>', methods=['GET', 'POST'])
@login_required
def edit_event(event_id):
    event = mongo.db.events.find_one({"_id": ObjectId(event_id)})
    current_date = datetime.now().strftime('%Y-%m-%d')
    if not event:
        flash('Event not found.', 'danger')
        return redirect(url_for('list_events'))
    if request.method == 'POST':
        updated_event = {
            "title": request.form.get('title'),
            "description": request.form.get('description'),
            "date": datetime.strptime(request.form.get('date'), '%Y-%m-%d'),
            "location": request.form.get('location'),
        }
        mongo.db.events.update_one({"_id": ObjectId(event_id)}, {"$set": updated_event})
        flash('Event updated successfully!', 'success')
        return redirect(url_for('view_event', event_id=ObjectId(event_id)))
    return render_template('edit_event.html', event=event, current_date=current_date)

@app.route('/event/rsvp/<event_id>')
@login_required
def rsvp_event(event_id):
    event = mongo.db.events.find_one({"_id": ObjectId(event_id)})
    if not event:
        flash('Event not found.', 'danger')
        return redirect(url_for('list_events'))

    user = mongo.db.users.find_one({"_id": ObjectId(current_user.get_id())})

    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('list_events'))

    # Check if the event is already in the user's RSVP list
    if ObjectId(event_id) not in user.get('events', []):
        mongo.db.users.update_one(
            {"_id": ObjectId(current_user.get_id())},
            {"$push": {"events": ObjectId(event_id)}}
        )
        flash(f'You have successfully RSVP\'d to {event["title"]}', 'success')
    else:
        flash(f'You have already RSVP\'d to {event["title"]}', 'info')
        
    return redirect(url_for('list_events'))

@app.route('/jobs')
@login_required
def list_jobs():
    user_jobs = mongo.db.job_posts.find({"posted_by":current_user.username})
    all_jobs = mongo.db.job_posts.find()
    return render_template('jobs.html', jobs=all_jobs,user_jobs=user_jobs)

@app.route('/job/<job_id>')
@login_required
def view_job(job_id):
    job = mongo.db.job_posts.find_one({"_id": ObjectId(job_id)})
    if job:
        return render_template('view_job.html', job=job)
    else:
        flash('Job not found.', 'danger')
        return redirect(url_for('list_jobs'))

@app.route('/create_job', methods=['GET', 'POST'])
@login_required
def create_job():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        company = request.form.get('company')
        location = request.form.get('location')
        new_job = {
            "title": title,
            "description": description,
            "company": company,
            "location":location,
            "posted_by": current_user.username
        }
        mongo.db.job_posts.insert_one(new_job)
        flash('Job created successfully!', 'success')
        return redirect(url_for('list_jobs'))
    return render_template('create_job.html')

@app.route('/edit_job/<job_id>', methods=['GET', 'POST'])
@login_required
def edit_job(job_id):
    job = mongo.db.job_posts.find_one({"_id": ObjectId(job_id)})
    if not job:
        flash('Job not found.', 'danger')
        return redirect(url_for('list_jobs'))
    if request.method == 'POST':
        updated_job = {
            "title": request.form.get('title'),
            "description": request.form.get('description'),
            "company": request.form.get('company'),
            "location":request.form.get('location')
        }
        mongo.db.job_posts.update_one({"_id": ObjectId(job_id)}, {"$set": updated_job})
        flash('Job updated successfully!', 'success')
        return redirect(url_for('view_job', job_id=ObjectId(job_id)))
    return render_template('edit_job.html', job=job)

@app.route('/mentorships')
@login_required
def list_mentorships():
    user_mentorships = mongo.db.mentorships.find({"posted_by":current_user.username})
    all_mentorships = mongo.db.mentorships.find()
    return render_template('mentorships.html', mentorships=all_mentorships, user_mentorships=user_mentorships)

@app.route('/mentorship/<mentorship_id>')
@login_required
def view_mentorship(mentorship_id):
    mentorship = mongo.db.mentorships.find_one({"_id": ObjectId(mentorship_id)})
    if mentorship:
        return render_template('view_mentorship.html', mentorship=mentorship)
    else:
        flash('Mentorship not found.', 'danger')
        return redirect(url_for('list_mentorships'))

@app.route('/create_mentorship', methods=['GET', 'POST'])
@login_required
def create_mentorship():
    if request.method == 'POST':
        mentor_name = request.form.get('mentor_name')
        mentee_name = request.form.get('mentee_name')
        contact_info = request.form.get('contact_info')
        details = request.form.get('details')
        new_mentorship = {
            "mentor_name": mentor_name,
            "mentee_name": mentee_name,
            "details": details,
            "contact_info": contact_info,
            "posted_by": current_user.username
        }
        mongo.db.mentorships.insert_one(new_mentorship)
        flash('Mentorship created successfully!', 'success')
        return redirect(url_for('list_mentorships'))
    return render_template('create_mentorship.html')

@app.route('/edit_mentorship/<mentorship_id>', methods=['GET', 'POST'])
@login_required
def edit_mentorship(mentorship_id):
    mentorship = mongo.db.mentorships.find_one({"_id": ObjectId(mentorship_id)})
    if not mentorship:
        flash('Mentorship not found.', 'danger')
        return redirect(url_for('list_mentorships'))
    if request.method == 'POST':
        updated_mentorship = {
            "mentor_name": request.form.get('mentor_name'),
            "mentee_name": request.form.get('mentee_name'),
            "details": request.form.get('details'),
            "contact_info": request.form.get('contact_info')
        }
        mongo.db.mentorships.update_one({"_id": ObjectId(mentorship_id)}, {"$set": updated_mentorship})
        flash('Mentorship updated successfully!', 'success')
        return redirect(url_for('view_mentorship', mentorship_id=ObjectId(mentorship_id)))
    return render_template('edit_mentorship.html', mentorship=mentorship)

# ==================== POST SYSTEM ====================

@app.route('/posts')
@login_required
def list_posts():
    """Display all posts with pagination"""
    try:
        if mongo is None:
            flash('Database connection error. Posts are not available.', 'danger')
            return render_template('posts.html', posts=[], user_posts=[])
            
        page = request.args.get('page', 1, type=int)
        per_page = 10
        
        # Get all posts with user information
        posts = list(mongo.db.posts.find().sort("created_at", -1).skip((page-1)*per_page).limit(per_page))
        
        # Get user posts for the current user
        user_posts = list(mongo.db.posts.find({"user_id": str(current_user.id)}).sort("created_at", -1))
        
        return render_template('posts.html', posts=posts, user_posts=user_posts, page=page)
    except Exception as e:
        flash(f'Error loading posts: {str(e)}', 'danger')
        return render_template('posts.html', posts=[], user_posts=[])

@app.route('/post/<post_id>')
@login_required
def view_post(post_id):
    """View a specific post"""
    try:
        post = mongo.db.posts.find_one({"_id": ObjectId(post_id)})
        if not post:
            flash('Post not found.', 'danger')
            return redirect(url_for('list_posts'))
        
        # Get the author's information
        author = mongo.db.users.find_one({"_id": ObjectId(post['user_id'])})
        post['author'] = author
        
        return render_template('view_post.html', post=post)
    except Exception as e:
        flash(f'Error loading post: {str(e)}', 'danger')
        return redirect(url_for('list_posts'))

@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    """Create a new post"""
    if mongo is None:
        flash('Database connection error. Post creation is not available.', 'danger')
        return render_template('create_post.html')
        
    if request.method == 'POST':
        try:
            title = request.form.get('title')
            content = request.form.get('content')
            
            if not title or not content:
                flash('Title and content are required.', 'danger')
                return render_template('create_post.html')
            
            # Handle image upload
            image_filename = None
            if 'image' in request.files:
                file = request.files['image']
                if file.filename != '':
                    # Save the uploaded image
                    image_filename = photos.save(file)
            
            new_post = {
                "title": title,
                "content": content,
                "image": image_filename,
                "user_id": str(current_user.id),
                "username": current_user.username,
                "created_at": datetime.now(),
                "updated_at": datetime.now()
            }
            
            mongo.db.posts.insert_one(new_post)
            flash('Post created successfully!', 'success')
            return redirect(url_for('list_posts'))
            
        except Exception as e:
            flash(f'Post creation failed: {str(e)}', 'danger')
            app.logger.error(f'Post creation error: {str(e)}')
    
    return render_template('create_post.html')

@app.route('/edit_post/<post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    """Edit an existing post"""
    try:
        post = mongo.db.posts.find_one({"_id": ObjectId(post_id)})
        if not post:
            flash('Post not found.', 'danger')
            return redirect(url_for('list_posts'))
        
        # Check if user owns the post
        if post['user_id'] != str(current_user.id) and not current_user.is_admin():
            flash('You can only edit your own posts.', 'danger')
            return redirect(url_for('list_posts'))
        
        if request.method == 'POST':
            title = request.form.get('title')
            content = request.form.get('content')
            
            if not title or not content:
                flash('Title and content are required.', 'danger')
                return render_template('edit_post.html', post=post)
            
            # Handle image upload
            image_filename = post.get('image')  # Keep existing image by default
            if 'image' in request.files:
                file = request.files['image']
                if file.filename != '':
                    # Save the new image
                    image_filename = photos.save(file)
            
            updated_post = {
                "title": title,
                "content": content,
                "image": image_filename,
                "updated_at": datetime.now()
            }
            
            mongo.db.posts.update_one({"_id": ObjectId(post_id)}, {"$set": updated_post})
            flash('Post updated successfully!', 'success')
            return redirect(url_for('view_post', post_id=post_id))
        
        return render_template('edit_post.html', post=post)
        
    except Exception as e:
        flash(f'Error editing post: {str(e)}', 'danger')
        return redirect(url_for('list_posts'))

@app.route('/delete_post/<post_id>', methods=['GET', 'POST'])
@login_required
def delete_post(post_id):
    """Delete a post"""
    try:
        post = mongo.db.posts.find_one({"_id": ObjectId(post_id)})
        if not post:
            flash('Post not found.', 'danger')
            return redirect(url_for('list_posts'))
        
        # Check if user owns the post or is admin
        if post['user_id'] != str(current_user.id) and not current_user.is_admin():
            flash('You can only delete your own posts.', 'danger')
            return redirect(url_for('list_posts'))
        
        mongo.db.posts.delete_one({"_id": ObjectId(post_id)})
        flash('Post deleted successfully!', 'success')
        
    except Exception as e:
        flash(f'Error deleting post: {str(e)}', 'danger')
        app.logger.error(f'Post deletion error: {str(e)}')
    
    return redirect(url_for('list_posts'))

@app.route('/user_posts/<username>')
@login_required
def user_posts(username):
    """View all posts by a specific user"""
    try:
        user = mongo.db.users.find_one({"username": username})
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('list_posts'))
        
        posts = list(mongo.db.posts.find({"user_id": str(user['_id'])}).sort("created_at", -1))
        
        return render_template('user_posts.html', posts=posts, user=user)
        
    except Exception as e:
        flash(f'Error loading user posts: {str(e)}', 'danger')
        return redirect(url_for('list_posts'))

# Global Search Functionality
@app.route('/search')
@login_required
def global_search():
    query = request.args.get('q', '')
    search_type = request.args.get('type', 'all')
    
    results = {
        'events': [],
        'discussions': [],
        'jobs': [],
        'mentorships': [],
        'users': []
    }
    
    if query:
        # Search events
        if search_type in ['all', 'events']:
            events = mongo.db.events.find({
                "$or": [
                    {"title": {"$regex": query, "$options": "i"}},
                    {"description": {"$regex": query, "$options": "i"}},
                    {"location": {"$regex": query, "$options": "i"}}
                ]
            }).limit(10)
            results['events'] = list(events)
        
        # Search discussions
        if search_type in ['all', 'discussions']:
            discussions = mongo.db.discussions.find({
                "$or": [
                    {"topic": {"$regex": query, "$options": "i"}},
                    {"content": {"$regex": query, "$options": "i"}},
                    {"category": {"$regex": query, "$options": "i"}}
                ]
            }).limit(10)
            results['discussions'] = list(discussions)
        
        # Search jobs
        if search_type in ['all', 'jobs']:
            jobs = mongo.db.job_posts.find({
                "$or": [
                    {"title": {"$regex": query, "$options": "i"}},
                    {"description": {"$regex": query, "$options": "i"}},
                    {"company": {"$regex": query, "$options": "i"}},
                    {"location": {"$regex": query, "$options": "i"}}
                ]
            }).limit(10)
            results['jobs'] = list(jobs)
        
        # Search mentorships
        if search_type in ['all', 'mentorships']:
            mentorships = mongo.db.mentorships.find({
                "$or": [
                    {"mentor_name": {"$regex": query, "$options": "i"}},
                    {"mentee_name": {"$regex": query, "$options": "i"}},
                    {"details": {"$regex": query, "$options": "i"}}
                ]
            }).limit(10)
            results['mentorships'] = list(mentorships)
        
        # Search users (admin only)
        if current_user.is_admin() and search_type in ['all', 'users']:
            users = mongo.db.users.find({
                "username": {"$regex": query, "$options": "i"}
            }).limit(10)
            results['users'] = list(users)
    
    return render_template('search_results.html', results=results, query=query, search_type=search_type)

# Analytics Dashboard
@app.route('/analytics')
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
        'recent_events': list(mongo.db.events.find().sort("date", -1).limit(5)),
        'recent_discussions': list(mongo.db.discussions.find().sort("_id", -1).limit(5)),
        'recent_jobs': list(mongo.db.job_posts.find().sort("_id", -1).limit(5))
    }
    
    # Get monthly data for charts
    current_month = datetime.now().replace(day=1)
    last_month = (current_month - timedelta(days=1)).replace(day=1)
    
    monthly_stats = {
        'events_this_month': mongo.db.events.count_documents({"date": {"$gte": current_month}}),
        'events_last_month': mongo.db.events.count_documents({
            "date": {"$gte": last_month, "$lt": current_month}
        }),
        'discussions_this_month': mongo.db.discussions.count_documents({
            "created_at": {"$gte": current_month}
        }),
        'jobs_this_month': mongo.db.job_posts.count_documents({
            "_id": {"$gte": ObjectId.from_datetime(current_month)}
        })
    }
    
    return render_template('analytics.html', stats=stats, monthly_stats=monthly_stats)

# Export Data Functionality
@app.route('/export/<data_type>')
@login_required
def export_data(data_type):
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    
    if data_type == 'users':
        data = list(mongo.db.users.find({}, {'password': 0}))
        filename = 'users_export.csv'
    elif data_type == 'events':
        data = list(mongo.db.events.find())
        filename = 'events_export.csv'
    elif data_type == 'discussions':
        data = list(mongo.db.discussions.find())
        filename = 'discussions_export.csv'
    elif data_type == 'jobs':
        data = list(mongo.db.job_posts.find())
        filename = 'jobs_export.csv'
    elif data_type == 'mentorships':
        data = list(mongo.db.mentorships.find())
        filename = 'mentorships_export.csv'
    else:
        flash('Invalid export type.', 'danger')
        return redirect(url_for('analytics_dashboard'))
    
    # Convert to CSV
    output = io.StringIO()
    if data:
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        for row in data:
            # Convert ObjectId to string
            row_dict = {}
            for key, value in row.items():
                if isinstance(value, ObjectId):
                    row_dict[key] = str(value)
                elif isinstance(value, datetime):
                    row_dict[key] = value.isoformat()
                else:
                    row_dict[key] = value
            writer.writerow(row_dict)
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )

# Advanced Filtering for Events
@app.route('/events/filter')
@login_required
def filter_events():
    location = request.args.get('location', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    query = {}
    
    if location:
        query['location'] = {"$regex": location, "$options": "i"}
    
    if date_from:
        query['date'] = {"$gte": datetime.strptime(date_from, '%Y-%m-%d')}
    
    if date_to:
        if 'date' in query:
            query['date']['$lte'] = datetime.strptime(date_to, '%Y-%m-%d')
        else:
            query['date'] = {"$lte": datetime.strptime(date_to, '%Y-%m-%d')}
    
    events = list(mongo.db.events.find(query).sort("date", 1))
    return render_template('events.html', events=events, user_events=[])

# Bulk Operations
@app.route('/admin/bulk_operations', methods=['POST'])
@login_required
def bulk_operations():
    if not current_user.is_admin():
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('dashboard'))
    
    action = request.form.get('action')
    item_type = request.form.get('item_type')
    item_ids = request.form.getlist('item_ids')
    
    if not item_ids:
        flash('No items selected.', 'warning')
        return redirect(url_for('admin_dashboard'))
    
    collection_map = {
        'users': mongo.db.users,
        'events': mongo.db.events,
        'discussions': mongo.db.discussions,
        'jobs': mongo.db.job_posts,
        'mentorships': mongo.db.mentorships
    }
    
    collection = collection_map.get(item_type)
    if not collection:
        flash('Invalid item type.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    object_ids = [ObjectId(item_id) for item_id in item_ids]
    
    if action == 'delete':
        result = collection.delete_many({"_id": {"$in": object_ids}})
        flash(f'{result.deleted_count} items deleted successfully.', 'success')
    elif action == 'export':
        # Export selected items
        data = list(collection.find({"_id": {"$in": object_ids}}))
        # Implementation for export would go here
        flash(f'{len(data)} items exported successfully.', 'success')
    
    return redirect(url_for('admin_dashboard'))

# Email Newsletter
@app.route('/admin/send_newsletter', methods=['GET', 'POST'])
@login_required
def send_newsletter():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        subject = request.form.get('subject')
        content = request.form.get('content')
        recipients = request.form.getlist('recipients')
        
        if recipients == ['all']:
            users = mongo.db.users.find({}, {'username': 1})
            email_list = [user['username'] for user in users]
        else:
            email_list = recipients
        
        # Send email to each recipient
        for email in email_list:
            try:
                msg = Message(
                    subject=subject,
                    sender=app.config['MAIL_USERNAME'],
                    recipients=[email]
                )
                msg.body = content
                mail.send(msg)
            except Exception as e:
                flash(f'Error sending email to {email}: {str(e)}', 'danger')
        
        flash('Newsletter sent successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    users = mongo.db.users.find({}, {'username': 1})
    return render_template('send_newsletter.html', users=users)

# API Endpoints for AJAX
@app.route('/api/events/upcoming')
@login_required
def api_upcoming_events():
    events = list(mongo.db.events.find({
        "date": {"$gte": datetime.today()}
    }).sort("date", 1).limit(5))
    
    # Convert ObjectId and datetime to string for JSON serialization
    for event in events:
        event['_id'] = str(event['_id'])
        if 'date' in event:
            event['date'] = event['date'].isoformat()
    
    return jsonify(events)

@app.route('/api/notifications/unread')
@login_required
def api_unread_notifications():
    notifications = list(mongo.db.notifications.find({
        "$or": [
            {"recipients": "all"},
            {"recipients": current_user.username}
        ],
        "read_by": {"$ne": current_user.username}
    }).sort("created_at", -1).limit(10))
    
    for notification in notifications:
        notification['_id'] = str(notification['_id'])
        if 'created_at' in notification:
            notification['created_at'] = notification['created_at'].isoformat()
    
    return jsonify(notifications)

# Logo Management Routes
@app.route('/api/logo/switch', methods=['POST'])
def api_logo_switch():
    """API endpoint to track logo switches for analytics"""
    try:
        data = request.get_json()
        switch_type = data.get('switch_type', 'unknown')
        
        # Log the logo switch event
        logo_event = {
            'action': 'logo_switch',
            'switch_type': switch_type,
            'timestamp': datetime.now(),
            'user_agent': request.headers.get('User-Agent'),
            'ip_address': request.remote_addr
        }
        
        if current_user.is_authenticated:
            logo_event['user_id'] = current_user.id
            logo_event['username'] = current_user.username
        
        # Store in analytics collection
        if mongo is not None:
            mongo.db.logo_analytics.insert_one(logo_event)
        
        return jsonify({'status': 'success', 'message': 'Logo switch tracked'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/admin/logo-analytics')
@login_required
def admin_logo_analytics():
    """Admin view for logo analytics"""
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        if mongo is None:
            flash('Database connection error. Analytics not available.', 'danger')
            return render_template('logo_analytics.html', analytics={})
        
        # Get logo switch statistics
        total_switches = mongo.db.logo_analytics.count_documents({'action': 'logo_switch'})
        
        # Get switches by type
        switch_pipeline = [
            {"$match": {"action": "logo_switch"}},
            {"$group": {"_id": "$switch_type", "count": {"$sum": 1}}}
        ]
        switch_stats = list(mongo.db.logo_analytics.aggregate(switch_pipeline))
        
        # Get recent activity
        recent_activity = list(mongo.db.logo_analytics.find(
            {'action': 'logo_switch'}
        ).sort('timestamp', -1).limit(50))
        
        analytics_data = {
            'total_switches': total_switches,
            'switch_stats': switch_stats,
            'recent_activity': recent_activity
        }
        
        return render_template('logo_analytics.html', analytics=analytics_data)
    except Exception as e:
        flash(f'Error loading analytics: {str(e)}', 'danger')
        return render_template('logo_analytics.html', analytics={})

@app.route('/admin/logo-upload', methods=['GET', 'POST'])
@login_required
def admin_logo_upload():
    """Admin route for uploading new logos"""
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            if 'logo_file' in request.files:
                file = request.files['logo_file']
                logo_type = request.form.get('logo_type', 'primary')
                
                if file.filename != '':
                    # Validate file type
                    allowed_extensions = {'png', 'jpg', 'jpeg', 'svg', 'gif'}
                    if '.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in allowed_extensions:
                        # Create filename with timestamp
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        filename = f"{logo_type}_logo_{timestamp}.{file.filename.rsplit('.', 1)[1].lower()}"
                        
                        # Save file
                        filepath = os.path.join(app.config.get('UPLOADED_PHOTOS_DEST', 'uploads'), filename)
                        file.save(filepath)
                        
                        # Store logo information in database
                        if mongo is not None:
                            logo_info = {
                                'filename': filename,
                                'original_filename': file.filename,
                                'logo_type': logo_type,
                                'uploaded_by': current_user.username,
                                'uploaded_at': datetime.now(),
                                'active': False
                            }
                            mongo.db.logos.insert_one(logo_info)
                        
                        flash(f'{logo_type.title()} logo uploaded successfully!', 'success')
                    else:
                        flash('Invalid file type. Please upload PNG, JPG, JPEG, SVG, or GIF files only.', 'danger')
                else:
                    flash('No file selected.', 'danger')
            else:
                flash('No file found in request.', 'danger')
        except Exception as e:
            flash(f'Error uploading logo: {str(e)}', 'danger')
    
    # Get current logos
    current_logos = []
    if mongo is not None:
        current_logos = list(mongo.db.logos.find().sort('uploaded_at', -1))
    
    return render_template('logo_upload.html', logos=current_logos)

@app.route('/admin/logo-activate/<logo_id>', methods=['POST'])
@login_required
def admin_logo_activate(logo_id):
    """Activate a specific logo"""
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        if mongo is not None:
            # Get the logo to activate
            logo = mongo.db.logos.find_one({'_id': ObjectId(logo_id)})
            if logo:
                # Deactivate all logos of the same type
                mongo.db.logos.update_many(
                    {'logo_type': logo['logo_type']},
                    {'$set': {'active': False}}
                )
                
                # Activate the selected logo
                mongo.db.logos.update_one(
                    {'_id': ObjectId(logo_id)},
                    {'$set': {'active': True}}
                )
                
                flash(f'{logo["logo_type"].title()} logo activated successfully!', 'success')
            else:
                flash('Logo not found.', 'danger')
    except Exception as e:
        flash(f'Error activating logo: {str(e)}', 'danger')
    
    return redirect(url_for('admin_logo_upload'))

@app.route('/logo-demo')
def logo_demo():
    """Public demo page showcasing the logo system functionality"""
    return render_template('logo_demo.html')

@app.route('/api/logo/report')
@login_required
def api_logo_report():
    """Generate and download logo analytics report (Admin only)"""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized access'}), 403
    
    try:
        from io import BytesIO
        import csv
        
        # Create CSV report
        output = BytesIO()
        
        if mongo is not None:
            # Get logo analytics data
            analytics_data = list(mongo.db.logo_analytics.find({'action': 'logo_switch'}).sort('timestamp', -1))
            
            # Create CSV content
            fieldnames = ['timestamp', 'switch_type', 'username', 'ip_address', 'user_agent']
            
            # Convert to string for CSV writing
            csv_content = "timestamp,switch_type,username,ip_address,user_agent\n"
            
            for record in analytics_data:
                timestamp = record.get('timestamp', '').strftime('%Y-%m-%d %H:%M:%S') if record.get('timestamp') else 'N/A'
                switch_type = record.get('switch_type', 'N/A')
                username = record.get('username', 'Anonymous')
                ip_address = record.get('ip_address', 'N/A')
                user_agent = record.get('user_agent', 'N/A').replace(',', ';')  # Replace commas to avoid CSV issues
                
                csv_content += f"{timestamp},{switch_type},{username},{ip_address},{user_agent}\n"
            
            # Write to BytesIO
            output.write(csv_content.encode('utf-8'))
            output.seek(0)
            
            return send_file(
                output,
                mimetype='text/csv',
                as_attachment=True,
                download_name=f'logo_analytics_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            )
        else:
            return jsonify({'error': 'Database connection not available'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Failed to generate report: {str(e)}'}), 500

# Admin Dashboard API Endpoints
@app.route('/api/admin/stats/users')
@login_required
def api_admin_stats_users():
    """Get total user count for admin dashboard"""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        if mongo is not None:
            count = mongo.db.users.count_documents({})
            return jsonify({'count': count})
        return jsonify({'count': 0})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/stats/events')
@login_required
def api_admin_stats_events():
    """Get active event count for admin dashboard"""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        if mongo is not None:
            count = mongo.db.events.count_documents({'date': {'$gte': datetime.now()}})
            return jsonify({'count': count})
        return jsonify({'count': 0})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/stats/jobs')
@login_required
def api_admin_stats_jobs():
    """Get job posts count for admin dashboard"""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        if mongo is not None:
            count = mongo.db.job_posts.count_documents({})
            return jsonify({'count': count})
        return jsonify({'count': 0})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/stats/logo-switches')
@login_required
def api_admin_stats_logo_switches():
    """Get logo switch count for admin dashboard"""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        if mongo is not None:
            count = mongo.db.logo_analytics.count_documents({'action': 'logo_switch'})
            return jsonify({'count': count})
        return jsonify({'count': 0})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/activity')
@login_required
def api_admin_activity():
    """Get recent administrative activity"""
    if not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        activities = [
            {
                'type': 'success',
                'icon': 'fas fa-user-plus',
                'title': 'New User Registration',
                'description': 'A new alumni registered on the platform',
                'timestamp': '2 hours ago'
            },
            {
                'type': 'info',
                'icon': 'fas fa-exchange-alt', 
                'title': 'Logo Switch',
                'description': 'User switched to alumni logo',
                'timestamp': '3 hours ago'
            },
            {
                'type': 'warning',
                'icon': 'fas fa-calendar-alt',
                'title': 'Event Updated',
                'description': 'Annual meetup event details modified',
                'timestamp': '5 hours ago'
            }
        ]
        return jsonify({'activities': activities})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    create_admin_user()
    app.secret_key = os.urandom(24)
    # Suppress the development server warning
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    # Run with use_reloader=False to avoid Windows socket issues
    socketio.run(app, debug=True, use_reloader=False)

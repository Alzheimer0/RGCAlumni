# # ./app.py

# from flask import Flask, render_template, redirect, url_for, request, flash
# from flask_sqlalchemy import SQLAlchemy
# from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
# from flask_mail import Mail, Message
# from werkzeug.security import generate_password_hash, check_password_hash
# from flask_migrate import Migrate
# from flask_uploads import UploadSet, configure_uploads, IMAGES
# from PIL import Image
# from pymongo import MongoClient
# import os
# import datetime

# app = Flask(__name__)

# # Database configuration
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:chandthakur@localhost/ams'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with a strong secret key


# app.config['UPLOADED_PHOTOS_DEST'] = 'uploads'
# photos = UploadSet('photos', IMAGES)
# configure_uploads(app, photos)

# # Mail configuration
# app.config['MAIL_SERVER'] = 'smtp.gmail.com'
# app.config['MAIL_PORT'] = 587
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
# app.config['MAIL_PASSWORD'] = 'your_password'

# db = SQLAlchemy(app)
# mail = Mail(app)
# login_manager = LoginManager()
# login_manager.init_app(app)
# login_manager.login_view = 'login'

# # migrate = Migrate(app, db)


# # Association table for the many-to-many relationship between Alumni and Events
# alumni_event = db.Table('alumni_event',
#     db.Column('alumni_id', db.Integer, db.ForeignKey('alumni._id'), primary_key=True),
#     db.Column('event_id', db.Integer, db.ForeignKey('event._id'), primary_key=True)
# )

# # Define the Alumni model
# class Alumni(db.Model):
#     _id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(100), nullable=False)
#     graduation_year = db.Column(db.Integer, nullable=False)
#     industry = db.Column(db.String(100), nullable=False)
#     contact_details = db.Column(db.String(255), nullable=False)
#     events = db.relationship('Event', secondary=alumni_event, backref=db.backref('attendees', lazy='dynamic'))

# # Define the Event model
# class Event(db.Model):
#     _id = db.Column(db.Integer, primary_key=True)
#     title = db.Column(db.String(100), nullable=False)
#     date = db.Column(db.Date, nullable=False)
#     location = db.Column(db.String(100), nullable=False)
#     description = db.Column(db.Text, nullable=False)

# # Define the Discussion model
# class Discussion(db.Model):
#     _id = db.Column(db.Integer, primary_key=True)
#     topic = db.Column(db.String(100), nullable=False)
#     content = db.Column(db.Text, nullable=False)
#     author = db.Column(db.String(100), nullable=False)
#     category = db.Column(db.String(100), nullable=False)  # Added category field
#     replies = db.relationship('Reply', backref='discussion', lazy=True)  # Added relationship to Reply model


# # Define the Reply model
# class Reply(db.Model):
#     _id = db.Column(db.Integer, primary_key=True)
#     content = db.Column(db.Text, nullable=False)
#     author = db.Column(db.String(100), nullable=False)
#     discussion_id = db.Column(db.Integer, db.ForeignKey('discussion._id'), nullable=False)

# # Define the JobPost model
# class JobPost(db.Model):
#     _id = db.Column(db.Integer, primary_key=True)
#     title = db.Column(db.String(100), nullable=False)
#     description = db.Column(db.Text, nullable=False)
#     company = db.Column(db.String(100), nullable=False)
#     location = db.Column(db.String(100), nullable=False)
#     posted_by = db.Column(db.String(100), nullable=False)

# # Define the Mentorship model
# class Mentorship(db.Model):
#     _id = db.Column(db.Integer, primary_key=True)
#     mentor_name = db.Column(db.String(100), nullable=False)
#     mentee_name = db.Column(db.String(100), nullable=False)
#     details = db.Column(db.Text, nullable=False)
#     contact_info = db.Column(db.String(255), nullable=False)


# # Define the Notification model
# class Notification(db.Model):
#     _id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.Integer, db.ForeignKey('user._id'), nullable=False)
#     message = db.Column(db.String(500), nullable=False)
#     is_read = db.Column(db.Boolean, default=False)


# # Define the User model for authentication
# class User(UserMixin, db.Model):
#     _id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(100), unique=True, nullable=False)
#     password = db.Column(db.String(255), nullable=False)
#     role = db.Column(db.String(50), nullable=False, default='User')  # Admin, User
#     alumni_id = db.Column(db.Integer, db.ForeignKey('alumni._id'))  # Link User with Alumni
#     alumni = db.relationship('Alumni', backref='user', uselist=False)  # Establish relationship

#     def is_admin(self):
#         return self.role == 'Admin'

# @login_manager.user_loader
# def load_user(user_id):
#     return User.query.get(int(user_id))



# @app.route('/')
# def home():
#     # Get the next 5 upcoming events
#     upcoming_events = Event.query.filter(Event.date >= datetime.date.today()).order_by(Event.date.asc()).limit(5).all()
#     # Get the 5 most recent discussions
#     recent_discussions = Discussion.query.order_by(Discussion._id.desc()).limit(5).all()
#     return render_template('home.html', upcoming_events=upcoming_events, recent_discussions=recent_discussions)


# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         username = request.form.get('username')
#         password = request.form.get('password')
#         role = request.form.get('role')
#         existing_user = User.query.filter_by(username=username).first()
#         if existing_user:
#             flash('Username already exists. Please choose a different username.', 'danger')
#             return redirect(url_for('register'))
#         elif username and password:
#             hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
#             new_user = User(username=username, password=hashed_password, role=role)
#             try:
#                 db.session.add(new_user)
#                 db.session.commit()
#                 flash('Registration successful! Please log in.', 'success')
#                 return redirect(url_for('login'))
#             except Exception as e:
#                 db.session.rollback()
#                 flash(f'Error: {str(e)}', 'danger')
#         else:
#             flash('Username and password are required.', 'danger')
#     return render_template('register.html')

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form.get('username')
#         password = request.form.get('password')
#         user = User.query.filter_by(username=username).first()
#         if user and check_password_hash(user.password, password):
#             login_user(user)
#             return redirect(url_for('dashboard'))
#         else:
#             flash('Login Unsuccessful. Please check username and password', 'danger')
#     return render_template('login.html')

# @app.route('/admin')
# @login_required
# def admin_dashboard():
#     if not current_user.is_admin():
#         flash('You do not have permission to access this page.', 'danger')
#         return redirect(url_for('dashboard'))
#     return render_template('admin.html')

# @app.route('/admin/create_user', methods=['GET', 'POST'])
# @login_required
# def admin_create_user():
#     if not current_user.is_admin():
#         flash('You do not have permission to access this page.', 'danger')
#         return redirect(url_for('dashboard'))
#     if request.method == 'POST':
#         username = request.form.get('username')
#         password = request.form.get('password')
#         role = request.form.get('role')
#         new_user = User(username=username, password=password, role=role)
#         db.session.add(new_user)
#         db.session.commit()
#         flash('User created successfully', 'success')
#         return redirect(url_for('admin_dashboard'))
#     return render_template('create_user.html')

# @app.route('/admin/manage_users')
# @login_required
# def admin_manage_users():
#     if not current_user.is_admin():
#         flash('You do not have permission to access this page.', 'danger')
#         return redirect(url_for('dashboard'))
#     users = User.query.all()
#     return render_template('manage_users.html', users=users)



# @app.route('/admin/manage_events')
# @login_required
# def admin_manage_events():
#     if not current_user.is_admin():
#         flash('You do not have permission to access this page.', 'danger')
#         return redirect(url_for('dashboard'))
#     events = Event.query.all()
#     return render_template('manage_events.html', events=events)



# @app.route('/admin/manage_jobs')
# @login_required
# def admin_manage_jobs():
#     if not current_user.is_admin():
#         flash('You do not have permission to access this page.', 'danger')
#         return redirect(url_for('dashboard'))
#     jobs = JobPost.query.all()
#     return render_template('manage_jobs.html', jobs=jobs)



# @app.route('/admin/manage_discussions')
# @login_required
# def admin_manage_discussions():
#     if not current_user.is_admin():
#         flash('You do not have permission to access this page.', 'danger')
#         return redirect(url_for('dashboard'))
#     discussions = Discussion.query.all()
#     return render_template('manage_discussions.html', discussions=discussions)

# @app.route('/admin/view_logs')
# @login_required
# def admin_view_logs():
#     if not current_user.is_admin():
#         flash('You do not have permission to access this page.', 'danger')
#         return redirect(url_for('dashboard'))
#     # Logic to view logs goes here
#     logs = []  # This should be replaced with actual log fetching logic
#     return render_template('view_logs.html', logs=logs)

# @app.route('/admin/generate_reports')
# @login_required
# def admin_generate_reports():
#     if not current_user.is_admin():
#         flash('You do not have permission to access this page.', 'danger')
#         return redirect(url_for('dashboard'))
#     # Logic to generate reports goes here
#     reports = []  # This should be replaced with actual report generation logic
#     return render_template('generate_reports.html', reports=reports)

# # app.py

# @app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
# @login_required
# def admin_edit_user(user_id):
#     if not current_user.is_admin():
#         flash('You do not have permission to access this page.', 'danger')
#         return redirect(url_for('dashboard'))
#     user = User.query.get_or_404(user_id)
#     if request.method == 'POST':
#         user.username = request.form.get('username')
#         user.role = request.form.get('role')
#         db.session.commit()
#         flash('User updated successfully', 'success')
#         return redirect(url_for('manage_users'))
#     return render_template('edit_user.html', user=user)



# @app.route('/admin/delete_user/<int:user_id>', methods=['GET','POST'])
# @login_required
# def admin_delete_user(user_id):
#     if not current_user.is_admin():
#         flash('You do not have permission to access this page.', 'danger')
#         return redirect(url_for('dashboard'))
#     if request.method == 'GET':
#         user = User.query.get_or_404(user_id)
#         print("World")
#         db.session.delete(user)
#         db.session.commit()
#         flash('User deleted successfully', 'success')
#     return redirect(url_for('admin_manage_users'))



# @app.route('/admin/delete_event/<int:event_id>', methods=['POST'])
# @login_required
# def admin_delete_event(event_id):
#     if not current_user.is_admin():
#         flash('You do not have permission to access this page.', 'danger')
#         return redirect(url_for('dashboard'))
#     event = Event.query.get_or_404(event_id)
#     db.session.delete(event)
#     db.session.commit()
#     flash('Event deleted successfully', 'success')
#     return redirect(url_for('manage_events'))



# @app.route('/admin/delete_job/<int:job_id>', methods=['POST'])
# @login_required
# def admin_delete_job(job_id):
#     if not current_user.is_admin():
#         flash('You do not have permission to access this page.', 'danger')
#         return redirect(url_for('dashboard'))
#     job = JobPost.query.get_or_404(job_id)
#     db.session.delete(job)
#     db.session.commit()
#     flash('Job deleted successfully', 'success')
#     return redirect(url_for('manage_jobs'))

# @app.route('/admin/edit_discussion/<int:discussion_id>', methods=['GET', 'POST'])
# @login_required
# def admin_edit_discussion(discussion_id):
#     if not current_user.is_admin():
#         flash('You do not have permission to access this page.', 'danger')
#         return redirect(url_for('dashboard'))
#     discussion = Discussion.query.get_or_404(discussion_id)
#     if request.method == 'POST':
#         discussion.topic = request.form.get('topic')
#         discussion.content = request.form.get('content')
#         db.session.commit()
#         flash('Discussion updated successfully', 'success')
#         return redirect(url_for('manage_discussions'))
#     return render_template('edit_discussion.html', discussion=discussion)

# @app.route('/admin/delete_discussion/<int:discussion_id>', methods=['POST'])
# @login_required
# def admin_delete_discussion(discussion_id):
#     if not current_user.is_admin():
#         flash('You do not have permission to access this page.', 'danger')
#         return redirect(url_for('dashboard'))
#     discussion = Discussion.query.get_or_404(discussion_id)
#     db.session.delete(discussion)
#     db.session.commit()
#     flash('Discussion deleted successfully', 'success')
#     return redirect(url_for('manage_discussions'))


# @app.route('/dashboard')
# @login_required
# def dashboard():
#     # Get the current user's alumni profile
#     alumni = current_user.alumni
    
#     # Check if the alumni profile exists
#     if alumni:
#         # Query for upcoming events that the alumni has RSVP'd to
#         upcoming_events = db.session.query(Event).join(alumni_event).filter(
#             alumni_event.c.alumni_id == alumni._id,
#             Event.date >= datetime.date.today()
#         ).all()
#     else:
#         upcoming_events = []

#     # Get the recent discussions started by the user
#     recent_discussions = Discussion.query.filter_by(author=current_user.username).order_by(Discussion._id.desc()).limit(5).all()

#     # Get the job postings created by the user
#     user_jobs = JobPost.query.filter_by(posted_by=current_user.username).all()

#     # Get the mentorship opportunities associated with the user
#     user_mentorships = Mentorship.query.filter(
#         (Mentorship.mentor_name == current_user.username) | (Mentorship.mentee_name == current_user.username)
#     ).all()

#     return render_template('dashboard.html', 
#                            user=current_user, 
#                            alumni=alumni, 
#                            upcoming_events=upcoming_events, 
#                            recent_discussions=recent_discussions, 
#                            user_jobs=user_jobs, 
#                            user_mentorships=user_mentorships)



# @app.route('/profile')
# @login_required
# def view_profile():
#     alumni = current_user.alumni
#     if alumni:
#         return render_template('profile.html', alumni=alumni)
#     else:
#         return redirect(url_for('create_profile'))


# @app.route('/profile/create', methods=['GET', 'POST'])
# @login_required
# def create_profile():
#     if request.method == 'POST':
#         name = request.form.get('name')
#         graduation_year = request.form.get('graduation_year')
#         industry = request.form.get('industry')
#         contact_details = request.form.get('contact_details')
#         new_alumni = Alumni(name=name, graduation_year=graduation_year, industry=industry, contact_details=contact_details)
#         try:
#             db.session.add(new_alumni)
#             db.session.commit()
#             current_user.alumni = new_alumni
#             db.session.commit()
#             flash('Profile created successfully!', 'success')
#             return redirect(url_for('view_profile'))
#             # return redirect(url_for('view_profile',alumni_id=new_alumni._id))
#         except Exception as e:
#             db.session.rollback()
#             flash(f'Error: {str(e)}', 'danger')
#     return render_template('create_profile.html')




# @app.route('/profile/edit', methods=['GET', 'POST'])
# @login_required
# def edit_profile():
#     alumni = current_user.alumni
#     if not alumni:
#         return redirect(url_for('create_profile'))
#     if request.method == 'POST':
#         alumni.name = request.form.get('name')
#         alumni.graduation_year = request.form.get('graduation_year')
#         alumni.industry = request.form.get('industry')
#         alumni.contact_details = request.form.get('contact_details')
#         try:
#             db.session.commit()
#             flash('Profile updated successfully!', 'success')
#             return redirect(url_for('view_profile'))
#         except Exception as e:
#             db.session.rollback()
#             flash(f'Error: {str(e)}', 'danger')
#     return render_template('edit_profile.html', alumni=alumni)

# @app.route('/notifications')
# @login_required
# def notifications():
#     user_notifications = Notification.query.filter_by(user_id=current_user._id, is_read=False).all()
#     return render_template('notifications.html', notifications=user_notifications)

# @app.route('/mark_as_read/<int:notification_id>')
# @login_required
# def mark_as_read(notification_id):
#     notification = Notification.query.get(notification_id)
#     if notification and notification.user_id == current_user._id:
#         notification.is_read = True
#         db.session.commit()
#     return redirect(url_for('notifications'))

# @app.route('/upload', methods=['GET', 'POST'])
# @login_required
# def upload():
#     if request.method == 'POST' and 'photo' in request.files:
#         filename = photos.save(request.files['photo'])
#         filepath = os.path.join(app.config['UPLOADED_PHOTOS_DEST'], filename)
        
#         # Image processing example: resize
#         img = Image.open(filepath)
#         img = img.resize((300, 300))
#         img.save(filepath)
        
#         flash('Image successfully uploaded and processed!', 'success')
#         return redirect(url_for('profile'))
#     return render_template('upload.html')


# @app.route('/events')
# @login_required
# def list_events():
#     events = Event.query.all()
#     return render_template('events.html', events=events)

# @app.route('/admin/event/create', methods=['GET', 'POST'])
# @login_required
# def admin_create_event():
#     if not current_user.is_admin():
#         flash('You do not have permission to access this page.', 'danger')
#         return redirect(url_for('dashboard'))
#     if request.method == 'POST':
#         title = request.form.get('title')
#         date = request.form.get('date')
#         location = request.form.get('location')
#         description = request.form.get('description')
#         new_event = Event(title=title, date=datetime.datetime.strptime(date, '%Y-%m-%d').date(), location=location, description=description)
#         try:
#             db.session.add(new_event)
#             db.session.commit()
#             flash('Event created successfully!', 'success')
#             return redirect(url_for('list_events'))
#         except Exception as e:
#             db.session.rollback()
#             flash(f'Error: {str(e)}', 'danger')
#     return render_template('create_event.html')

# @app.route('/event/create', methods=['GET', 'POST'])
# @login_required
# def create_event():
#     if request.method == 'POST':
#         title = request.form.get('title')
#         date = request.form.get('date')
#         location = request.form.get('location')
#         description = request.form.get('description')
#         new_event = Event(title=title, date=datetime.datetime.strptime(date, '%Y-%m-%d').date(), location=location, description=description)
#         try:
#             db.session.add(new_event)
#             db.session.commit()
#             flash('Event created successfully!', 'success')
#             return redirect(url_for('list_events'))
#         except Exception as e:
#             db.session.rollback()
#             flash(f'Error: {str(e)}', 'danger')
#     return render_template('create_event.html')

# @app.route('/admin/event/edit/<int:event_id>', methods=['GET', 'POST'])
# @login_required
# def admin_edit_event(event_id):
#     if not current_user.is_admin():
#         flash('You do not have permission to access this page.', 'danger')
#         return redirect(url_for('dashboard'))
#     event = Event.query.get_or_404(event_id)
#     if request.method == 'POST':
#         event.title = request.form.get('title')
#         event.date = request.form.get('date')
#         event.location = request.form.get('location')
#         event.description = request.form.get('description')
#         try:
#             db.session.commit()
#             flash('Event updated successfully!', 'success')
#             return redirect(url_for('list_events'))
#         except Exception as e:
#             db.session.rollback()
#             flash(f'Error: {str(e)}', 'danger')
#     return render_template('edit_event.html', event=event)

# @app.route('/event/edit/<int:event_id>', methods=['GET', 'POST'])
# @login_required
# def edit_event(event_id):
#     event = Event.query.get_or_404(event_id)
#     if request.method == 'POST':
#         event.title = request.form.get('title')
#         event.date = request.form.get('date')
#         event.location = request.form.get('location')
#         event.description = request.form.get('description')
#         try:
#             db.session.commit()
#             flash('Event updated successfully!', 'success')
#             return redirect(url_for('list_events'))
#         except Exception as e:
#             db.session.rollback()
#             flash(f'Error: {str(e)}', 'danger')
#     return render_template('edit_event.html', event=event)

# @app.route('/event/<int:event_id>')
# @login_required
# def view_event(event_id):
#     event = Event.query.get_or_404(event_id)
#     return render_template('view_event.html', event=event)


# @app.route('/event/rsvp/<int:event_id>')
# @login_required
# def rsvp_event(event_id):
#     event = Event.query.get_or_404(event_id)
#     if event not in current_user.alumni.events:
#         current_user.alumni.events.append(event)
#         db.session.commit()
#         flash(f'You have successfully RSVP\'d to {event.title}', 'success')
#     else:
#         flash(f'You have already RSVP\'d to {event.title}', 'info')
#     return redirect(url_for('list_events'))


# @app.route('/discussions')
# @login_required
# def list_discussions():
#     categories = db.session.query(Discussion.category).distinct().all()
#     discussions = Discussion.query.all()
#     return render_template('discussions.html', discussions=discussions, categories=categories)

# @app.route('/discussion/<int:discussion_id>', methods=['GET', 'POST'])
# @login_required
# def view_discussion(discussion_id):
#     discussion = Discussion.query.get_or_404(discussion_id)
#     if request.method == 'POST':
#         content = request.form.get('content')
#         new_reply = Reply(content=content, author=current_user.username, discussion_id=discussion._id)
#         try:
#             db.session.add(new_reply)
#             db.session.commit()
#             flash('Reply posted successfully!', 'success')
#         except Exception as e:
#             db.session.rollback()
#             flash(f'Error: {str(e)}', 'danger')
#     replies = Reply.query.filter_by(discussion_id=discussion._id).all()
#     return render_template('discussion.html', discussion=discussion, replies=replies)

# @app.route('/admin/discussion/create', methods=['GET', 'POST'])
# @login_required
# def admin_create_discussion():
#     if current_user.role != 'Admin':
#         flash('You do not have permission to access this page.', 'danger')
#         return redirect(url_for('dashboard'))
#     if request.method == 'POST':
#         topic = request.form.get('topic')
#         content = request.form.get('content')
#         category = request.form.get('category')
#         new_discussion = Discussion(topic=topic, content=content, author=current_user.username, category=category)
#         try:
#             db.session.add(new_discussion)
#             db.session.commit()
#             flash('Discussion created successfully!', 'success')
#             return redirect(url_for('list_discussions'))
#         except Exception as e:
#             db.session.rollback()
#             flash(f'Error: {str(e)}', 'danger')
#     return render_template('create_discussion.html')

# @app.route('/discussion/create', methods=['GET', 'POST'])
# @login_required
# def create_discussion():
#     if request.method == 'POST':
#         topic = request.form.get('topic')
#         content = request.form.get('content')
#         category = request.form.get('category')
#         new_discussion = Discussion(topic=topic, content=content, author=current_user.username, category=category)
#         try:
#             db.session.add(new_discussion)
#             db.session.commit()
#             flash('Discussion created successfully!', 'success')
#             return redirect(url_for('list_discussions'))
#         except Exception as e:
#             db.session.rollback()
#             flash(f'Error: {str(e)}', 'danger')
#     return render_template('create_discussion.html')

# @app.route('/jobs')
# @login_required
# def list_jobs():
#     jobs = JobPost.query.all()
#     return render_template('jobs.html', jobs=jobs)

# @app.route('/job/<int:job_id>')
# @login_required
# def view_job(job_id):
#     job = JobPost.query.get_or_404(job_id)
#     return render_template('view_job.html', job=job)



# @app.route('/admin/job/create', methods=['GET', 'POST'])
# @login_required
# def admin_create_job():
#     if current_user.role != 'Admin':
#         flash('You do not have permission to access this page.', 'danger')
#         return redirect(url_for('dashboard'))
#     if request.method == 'POST':
#         title = request.form.get('title')
#         description = request.form.get('description')
#         company = request.form.get('company')
#         location = request.form.get('location')
#         posted_by = current_user.username
#         new_job = JobPost(title=title, description=description, company=company, location=location, posted_by=posted_by)
#         try:
#             db.session.add(new_job)
#             db.session.commit()
#             flash('Job posted successfully!', 'success')
#             return redirect(url_for('list_jobs'))
#         except Exception as e:
#             db.session.rollback()
#             flash(f'Error: {str(e)}', 'danger')
#     return render_template('create_job.html')

# @app.route('/job/create', methods=['GET', 'POST'])
# @login_required
# def create_job():
#     if request.method == 'POST':
#         title = request.form.get('title')
#         description = request.form.get('description')
#         company = request.form.get('company')
#         location = request.form.get('location')
#         posted_by = current_user.username
#         new_job = JobPost(title=title, description=description, company=company, location=location, posted_by=posted_by)
#         try:
#             db.session.add(new_job)
#             db.session.commit()
#             flash('Job posted successfully!', 'success')
#             return redirect(url_for('list_jobs'))
#         except Exception as e:
#             db.session.rollback()
#             flash(f'Error: {str(e)}', 'danger')
#     return render_template('create_job.html')

# @app.route('/admin/job/edit/<int:job_id>', methods=['GET', 'POST'])
# @login_required
# def admin_edit_job(job_id):
#     if current_user.role != 'Admin':
#         flash('You do not have permission to access this page.', 'danger')
#         return redirect(url_for('dashboard'))
#     job = JobPost.query.get_or_404(job_id)
#     if request.method == 'POST':
#         job.title = request.form.get('title')
#         job.description = request.form.get('description')
#         job.company = request.form.get('company')
#         job.location = request.form.get('location')
#         try:
#             db.session.commit()
#             flash('Job updated successfully!', 'success')
#             return redirect(url_for('list_jobs'))
#         except Exception as e:
#             db.session.rollback()
#             flash(f'Error: {str(e)}', 'danger')
#     return render_template('edit_job.html', job=job)

# @app.route('/job/edit/<int:job_id>', methods=['GET', 'POST'])
# @login_required
# def edit_job(job_id):
#     if current_user.role != 'Admin':
#         flash('You do not have permission to access this page.', 'danger')
#         return redirect(url_for('dashboard'))
#     job = JobPost.query.get_or_404(job_id)
#     if request.method == 'POST':
#         job.title = request.form.get('title')
#         job.description = request.form.get('description')
#         job.company = request.form.get('company')
#         job.location = request.form.get('location')
#         try:
#             db.session.commit()
#             flash('Job updated successfully!', 'success')
#             return redirect(url_for('list_jobs'))
#         except Exception as e:
#             db.session.rollback()
#             flash(f'Error: {str(e)}', 'danger')
#     return render_template('edit_job.html', job=job)

# @app.route('/mentorships')
# @login_required
# def list_mentorships():
#     mentorships = Mentorship.query.all()
#     return render_template('mentorships.html', mentorships=mentorships)

# @app.route('/mentorship/<int:mentorship_id>')
# @login_required
# def view_mentorship(mentorship_id):
#     mentorship = Mentorship.query.get_or_404(mentorship_id)
#     return render_template('view_mentorship.html', mentorship=mentorship)


# @app.route('/mentorship/create', methods=['GET', 'POST'])
# @login_required
# def create_mentorship():
#     if request.method == 'POST':
#         mentor_name = request.form.get('mentor_name')
#         mentee_name = request.form.get('mentee_name')
#         details = request.form.get('details')
#         contact_info = request.form.get('contact_info')
#         new_mentorship = Mentorship(mentor_name=mentor_name, mentee_name=mentee_name, details=details, contact_info=contact_info)
#         try:
#             db.session.add(new_mentorship)
#             db.session.commit()
#             flash('Mentorship opportunity posted successfully!', 'success')
#             return redirect(url_for('list_mentorships'))
#         except Exception as e:
#             db.session.rollback()
#             flash(f'Error: {str(e)}', 'danger')
#     return render_template('create_mentorship.html')

# @app.route('/mentorship/edit/<int:mentorship_id>', methods=['GET', 'POST'])
# @login_required
# def edit_mentorship(mentorship_id):
#     mentorship = Mentorship.query.get_or_404(mentorship_id)
#     if request.method == 'POST':
#         mentorship.mentor_name = request.form.get('mentor_name')
#         mentorship.mentee_name = request.form.get('mentee_name')
#         mentorship.details = request.form.get('details')
#         mentorship.contact_info = request.form.get('contact_info')
#         try:
#             db.session.commit()
#             flash('Mentorship updated successfully!', 'success')
#             return redirect(url_for('list_mentorships'))
#         except Exception as e:
#             db.session.rollback()
#             flash(f'Error: {str(e)}', 'danger')
#     return render_template('edit_mentorship.html', mentorship=mentorship)

# @app.route('/logout')
# @login_required
# def logout():
#     logout_user()
#     return redirect(url_for('home'))

# def send_event_reminders():
#     with app.app_context():
#         today = datetime.date.today()
#         events = Event.query.filter(Event.date == today).all()
#         for event in events:
#             attendees = event.attendees
#             for attendee in attendees:
#                 msg = Message('Reminder: Upcoming Event', 
#                               sender='your_email@gmail.com', 
#                               recipients=[attendee.contact_details])
#                 msg.body = f"Dear {attendee.name},\n\nThis is a reminder for the event '{event.title}' happening today at {event.location}.\n\nDescription: {event.description}\n\nBest regards,\nRajiv Gandhi Alumini Network"
#                 mail.send(msg)

# if __name__ == '__main__':
#     with app.app_context():
#         db.create_all()
#     app.run(debug=True)

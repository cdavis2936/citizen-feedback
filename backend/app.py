import os
import secrets
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, redirect, url_for, request, jsonify, session
from flask_mail import Mail
from flask_wtf import FlaskForm
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from wtforms import StringField, PasswordField, BooleanField, TextAreaField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo
from dotenv import load_dotenv
from flask_cors import CORS
from flask_wtf.file import FileField, FileAllowed
from flask_socketio import SocketIO, join_room
from pymongo import MongoClient
from bson import ObjectId
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Load environment variables from the .env file
load_dotenv()

# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'cmfs_secret_key_change_this_in_production')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
frontend_origins = os.getenv(
    'FRONTEND_ORIGINS',
    'http://localhost:3000,http://127.0.0.1:3000'
)
allowed_origins = [origin.strip() for origin in frontend_origins.split(',') if origin.strip()]
CORS(app, supports_credentials=True, origins=allowed_origins, methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
socketio = SocketIO(
    app,
    cors_allowed_origins=allowed_origins,
    async_mode='threading',
    logger=False,
    engineio_logger=False
)
connected_users = {}  # user_id -> set(socket_sid)
sid_to_user = {}  # socket_sid -> user_id

# Define base directory
basedir = os.path.abspath(os.path.dirname(__file__))

# Configurations

# MongoDB configuration
MONGO_HOST = os.getenv('MONGO_HOST', 'localhost')
MONGO_PORT = int(os.getenv('MONGO_PORT', 27017))
MONGO_DB = os.getenv('MONGO_DB', 'citizen_feedback')
MONGO_USERNAME = os.getenv('MONGO_USERNAME', '')
MONGO_PASSWORD = os.getenv('MONGO_PASSWORD', '')

# Connect to MongoDB
if MONGO_USERNAME and MONGO_PASSWORD:
    mongo_uri = f"mongodb://{MONGO_USERNAME}:{MONGO_PASSWORD}@{MONGO_HOST}:{MONGO_PORT}/{MONGO_DB}"
else:
    mongo_uri = f"mongodb://{MONGO_HOST}:{MONGO_PORT}/{MONGO_DB}"

client = MongoClient(mongo_uri)
db = client[MONGO_DB]

app.config['CORS_HEADERS'] = 'Content-Type'

# Upload folder and allowed extensions
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp', 'svg', 'mp4', 'mp3', 'wav', 'pdf', 'doc', 'docx'}
app.config['WTF_CSRF_ENABLED'] = True  # CSRF protection enabled
PROFILE_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp', 'svg'}

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
mail = Mail(app)

# Flask-Mail configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'False').lower() == 'true'
app.config['MAIL_USE_AUTH'] = os.getenv('MAIL_USE_AUTH', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@cmfs.com')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Set login view

# Collections for MongoDB
users_collection = db.users
feedbacks_collection = db.feedbacks
comments_collection = db.comments
likes_dislikes_collection = db.likes_dislikes
password_reset_tokens_collection = db.password_reset_tokens
projects_collection = db.projects
conversations_collection = db.conversations
messages_collection = db.messages

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    try:
        user_data = users_collection.find_one({'_id': ObjectId(user_id)})
        if user_data:
            return User(user_data)
        return None
    except Exception as e:
        logging.error(f"Error loading user: {str(e)}")
        return None

# Unauthorized handler returns JSON response
@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({"error": "Unauthorized"}), 401

# Allowed file checker
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def allowed_profile_image(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in PROFILE_IMAGE_EXTENSIONS

# Custom User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.email = user_data['email']
        self.password = user_data.get('password')
        self.is_admin = user_data.get('is_admin', False)
        self._data = user_data
    
    @staticmethod
    def get(user_id):
        try:
            user_data = users_collection.find_one({'_id': ObjectId(user_id)})
            if user_data:
                return User(user_data)
            return None
        except Exception as e:
            logging.error(f"Error getting user: {str(e)}")
            return None

# Forms
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('confirm_password')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class FeedbackForm(FlaskForm):
    category = StringField("Category", validators=[DataRequired()])
    description = TextAreaField("Description", validators=[DataRequired()])
    anonymous = BooleanField("Submit anonymously")
    photo = FileField("Upload Photo", validators=[FileAllowed(app.config['ALLOWED_EXTENSIONS'], 'Images only!')])
    submit = SubmitField("Submit")

class CommentForm(FlaskForm):
    content = TextAreaField('Comment', validators=[DataRequired()])
    submit = SubmitField('Submit Comment')

class FeedbackFilterForm(FlaskForm):
    category = SelectField('Category', choices=[
        ('All', 'All'),
        ('Infrastructure', 'Infrastructure'),
        ('Security', 'Security'),
        ('Health', 'Health'),
        ('Education', 'Education')
    ])
    submit = SubmitField('Filter')

# API Endpoints

# JWT Configuration (moved before routes that use these decorators)
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
if not JWT_SECRET_KEY:
    # Only allow fallback in development, not production
    import sys
    if 'production' in sys.argv or os.getenv('FLASK_ENV') == 'production':
        raise ValueError("JWT_SECRET_KEY environment variable must be set in production")
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'dev_only_change_this_in_production_12345')
JWT_ALGORITHM = 'HS256'
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

def create_jwt_token(user_data):
    """Create a JWT token for mobile authentication"""
    expire = datetime.utcnow() + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        'user_id': user_data.get('id'),
        'username': user_data.get('username'),
        'email': user_data.get('email'),
        'is_admin': user_data.get('is_admin', False),
        'exp': expire,
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def decode_jwt_token(token):
    """Decode and verify a JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def mobile_login_required(f):
    """Decorator for mobile API endpoints that require JWT authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid authorization header'}), 401
        
        token = auth_header.split(' ')[1]
        payload = decode_jwt_token(token)
        
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Add user info to request
        request.mobile_user = payload
        return f(*args, **kwargs)
    return decorated_function


def api_login_required(f):
    """Decorator that accepts both Flask-Login session and JWT token"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # First check if user is logged in via Flask-Login session
        if current_user.is_authenticated:
            return f(*args, **kwargs)
        
        # If not, check for JWT token in Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            payload = decode_jwt_token(token)
            
            if payload:
                user_id = payload.get('user_id')
                if not user_id:
                    return jsonify({'error': 'Unauthorized'}), 401

                try:
                    user_data = users_collection.find_one({'_id': ObjectId(user_id)})
                except Exception:
                    user_data = None

                if user_data:
                    login_user(User(user_data))
                    return f(*args, **kwargs)
        
        return jsonify({'error': 'Unauthorized'}), 401
    return decorated_function

def get_socket_user_from_auth(auth):
    """Get user payload from Socket.IO auth token."""
    if not auth:
        return None
    token = auth.get('token')
    if not token:
        return None
    return decode_jwt_token(token)

def is_user_connected(user_id):
    return bool(connected_users.get(str(user_id)))

@socketio.on('connect')
def handle_socket_connect(auth):
    try:
        payload = get_socket_user_from_auth(auth)
        if not payload:
            return False

        user_id = payload.get('user_id')
        if not user_id:
            return False

        user_id = str(user_id)
        sid = request.sid
        sid_to_user[sid] = user_id
        connected_users.setdefault(user_id, set()).add(sid)
        join_room(f"user_{user_id}")

        # Mark pending undelivered messages as delivered when user connects.
        undelivered = list(messages_collection.find({
            'recipient_id': ObjectId(user_id),
            'delivered': {'$ne': True}
        }, {'_id': 1, 'sender_id': 1}))
        if undelivered:
            message_ids = [msg['_id'] for msg in undelivered]
            now = datetime.utcnow()
            messages_collection.update_many(
                {'_id': {'$in': message_ids}},
                {'$set': {'delivered': True, 'delivered_at': now}}
            )
            for msg in undelivered:
                socketio.emit('message_status', {
                    'message_id': str(msg['_id']),
                    'conversation_id': None,
                    'delivered': True,
                    'read': False,
                    'delivered_at': now.isoformat(),
                    'read_at': None
                }, room=f"user_{str(msg['sender_id'])}")
    except Exception as e:
        logging.error("Socket connect error: %s", str(e))
        return False

@socketio.on('disconnect')
def handle_socket_disconnect():
    sid = request.sid
    user_id = sid_to_user.pop(sid, None)
    if user_id and user_id in connected_users:
        connected_users[user_id].discard(sid)
        if not connected_users[user_id]:
            connected_users.pop(user_id, None)
    logging.debug("Socket client disconnected")

# Get all feedback with respective comment and like/dislike counts (secured by login_required)
@app.route('/api/feedback', methods=['GET'])
@api_login_required
def get_feedback():
    feedbacks = list(feedbacks_collection.find().sort('timestamp', -1))
    feedback_list = []

    for feedback in feedbacks:
        feedback_id = feedback['_id']
        likes_count = likes_dislikes_collection.count_documents({'feedback_id': feedback_id, 'like': True})
        dislikes_count = likes_dislikes_collection.count_documents({'feedback_id': feedback_id, 'like': False})
        
        comments = list(comments_collection.find({'feedback_id': feedback_id}))

        feedback_data = {
            'id': str(feedback_id),
            'category': feedback['category'],
            'description': feedback['description'],
            'anonymous': feedback.get('anonymous', False),
            'image_url': feedback.get('image_url') or (
                url_for('static', filename=f"uploads/{feedback.get('photo_filename')}", _external=True)
                if feedback.get('photo_filename') else None
            ),
            'timestamp': feedback['timestamp'].isoformat() if feedback.get('timestamp') else None,
            'user_id': str(feedback['user_id']) if feedback.get('user_id') else None,
            'likes': likes_count,
            'dislikes': dislikes_count,
            'comments': [
                {
                    'id': str(comment['_id']),
                    'content': comment['content'],
                    'timestamp': comment['timestamp'].isoformat() if comment.get('timestamp') else None,
                    'user_id': str(comment['user_id'])
                } for comment in comments
            ]
        }
        feedback_list.append(feedback_data)

    return jsonify(feedback_list)

# Add comment to a feedback entry
@app.route('/api/feedback/<feedback_id>/comment', methods=['POST'])
@api_login_required
def add_comment(feedback_id):
    data = request.get_json()
    comment_text = data.get('comment')
    if not comment_text:
        return jsonify({"error": "Comment cannot be empty"}), 400

    try:
        feedback = feedbacks_collection.find_one({'_id': ObjectId(feedback_id)})
    except:
        return jsonify({"error": "Invalid feedback ID"}), 400
    
    if not feedback:
        return jsonify({"error": "Feedback not found"}), 404

    new_comment = {
        'content': comment_text,
        'user_id': ObjectId(current_user.id),
        'feedback_id': ObjectId(feedback_id),
        'timestamp': datetime.utcnow()
    }

    try:
        comments_collection.insert_one(new_comment)
        return jsonify({"message": "Comment added successfully!"}), 201
    except Exception as e:
        return jsonify({"error": f"Failed to add comment: {str(e)}"}), 500

# User registration endpoint
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({"error": "Username, email, and password are required."}), 400

    if users_collection.find_one({'username': username}):
        return jsonify({"error": "Username already exists"}), 400

    hashed_password = generate_password_hash(password)
    user_data = {
        'username': username,
        'email': email,
        'password': hashed_password,
        'is_admin': False
    }
    
    try:
        result = users_collection.insert_one(user_data)
        return jsonify({"message": "Registration successful!"}), 201
    except Exception as e:
        return jsonify({"error": f"Failed to register: {str(e)}"}), 500

# Handle preflight requests properly
@app.before_request
def handle_options_request():
    if request.method == 'OPTIONS':
        return jsonify({"message": "OK"}), 200

# Login endpoint using Flask-Login (no JWT, CSRF protection removed)
@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        # Ensure request content type is JSON
        if not request.is_json:
            return jsonify({"error": "Invalid content type. JSON expected."}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON data"}), 400

        username = data.get('username')
        password = data.get('password')

        # Logging for debugging (sanitized - only username, no password)
        logging.debug("Login attempt for user: %s", username)

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        user_data = users_collection.find_one({'username': username})
        if user_data and check_password_hash(user_data['password'], password):
            # Regenerate session to prevent session fixation attacks
            session.clear()
            session.permanent = True
            
            user = User(user_data)
            login_user(user)
            
            # Create JWT token
            user_payload = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin,
                'profile_photo_url': user_data.get('profile_photo_url')
            }
            token = create_jwt_token(user_payload)
            
            return jsonify({
                "message": "Login successful",
                "token": token,
                "user": user_payload
            }), 200
        else:
            return jsonify({"error": "Invalid username or password"}), 401
    except Exception as e:
        logging.error("Login error: %s", str(e))
        return jsonify({"error": "An error occurred during login"}), 500


# Submit feedback endpoint (handles file uploads and form data)
@app.route('/api/feedback', methods=['POST'])
def api_feedback():
    # Log request metadata only (not sensitive data like passwords or content)
    logging.debug(f"Request content type: {request.content_type}")
    
    # Try to get data from form or JSON
    filename = None
    image_url = None
    
    if request.is_json:
        data = request.get_json()
        category = data.get('category')
        description = data.get('description')
        anonymous = data.get('anonymous', False)
        image_base64 = data.get('image')
        filename = data.get('filename')
        
        # Handle base64 image
        if image_base64 and filename:
            try:
                import base64
                import uuid
                # Extract the actual base64 data (remove data URL prefix if present)
                if ',' in image_base64:
                    image_base64 = image_base64.split(',')[1]
                
                # Decode and save the file
                image_data = base64.b64decode(image_base64)
                
                # Generate a secure filename to prevent path traversal
                secure_name = secure_filename(filename)
                if not secure_name or secure_name.startswith('.'):
                    # Generate random filename if invalid
                    ext = secure_name.split('.')[-1] if '.' in secure_name else 'png'
                    secure_name = f"{uuid.uuid4().hex}.{ext}"
                
                # Additional path traversal check
                if '..' in secure_name or '/' in secure_name or '\\' in secure_name:
                    return jsonify({"error": "Invalid filename"}), 400
                
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_name)
                
                # Verify the final path is within the upload folder
                upload_dir = os.path.abspath(app.config['UPLOAD_FOLDER'])
                filepath = os.path.abspath(filepath)
                if not filepath.startswith(upload_dir):
                    return jsonify({"error": "Invalid file path"}), 400
                
                with open(filepath, 'wb') as f:
                    f.write(image_data)
                image_url = url_for('static', filename=f'uploads/{secure_name}', _external=True)
            except Exception as e:
                logging.error(f"Error saving image: {e}")
    else:
        category = request.form.get('category')
        description = request.form.get('description')
        anonymous = request.form.get('anonymous', 'false').lower() == 'true'
        
        # Handle file upload
        photo = request.files.get('photo')
        
        if photo:
            if photo.filename == '':
                return jsonify({"error": "No selected file"}), 400

            if allowed_file(photo.filename):
                import uuid
                filename = secure_filename(photo.filename)
                
                # Additional path traversal check
                if '..' in filename or '/' in filename or '\\' in filename:
                    return jsonify({"error": "Invalid filename"}), 400
                
                # Generate unique filename to prevent overwrites
                ext = filename.split('.')[-1] if '.' in filename else ''
                filename = f"{uuid.uuid4().hex}.{ext}" if ext else uuid.uuid4().hex
                
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                
                # Verify the final path is within the upload folder
                upload_dir = os.path.abspath(app.config['UPLOAD_FOLDER'])
                filepath = os.path.abspath(filepath)
                if not filepath.startswith(upload_dir):
                    return jsonify({"error": "Invalid file path"}), 400
                
                photo.save(filepath)
                image_url = url_for('static', filename=f'uploads/{filename}', _external=True)
            else:
                return jsonify({"error": "Invalid file type"}), 400

    if not category or not description:
        return jsonify({"error": "Category and description are required."}), 400

    user_id = None
    if not anonymous and current_user.is_authenticated:
        user_id = ObjectId(current_user.id)

    feedback_data = {
        'category': category,
        'description': description,
        'anonymous': anonymous,
        'photo_filename': filename,
        'image_url': image_url,
        'timestamp': datetime.utcnow(),
        'user_id': user_id,
        'likes': 0,
        'dislikes': 0
    }

    try:
        result = feedbacks_collection.insert_one(feedback_data)
        socketio.emit('new_feedback', {
            'id': str(result.inserted_id),
            'category': category
        })
        return jsonify({"message": "Feedback submitted successfully!", "image_url": image_url}), 201
    except Exception as e:
        return jsonify({"error": f"Failed to submit feedback: {str(e)}"}), 500

# Like a feedback entry
@app.route('/api/feedback/<feedback_id>/like', methods=['POST'])
@api_login_required
def api_like_feedback(feedback_id):
    try:
        feedback = feedbacks_collection.find_one({'_id': ObjectId(feedback_id)})
    except:
        return jsonify({"error": "Invalid feedback ID"}), 400
    
    if not feedback:
        return jsonify({"error": "Feedback not found"}), 404
    
    existing_like = likes_dislikes_collection.find_one({
        'feedback_id': ObjectId(feedback_id), 
        'user_id': ObjectId(current_user.id)
    })

    if existing_like:
        return jsonify({"error": "You have already interacted with this feedback."}), 400

    like_data = {
        'feedback_id': ObjectId(feedback_id),
        'user_id': ObjectId(current_user.id),
        'like': True,
        'timestamp': datetime.utcnow()
    }
    
    try:
        likes_dislikes_collection.insert_one(like_data)
        feedbacks_collection.update_one(
            {'_id': ObjectId(feedback_id)},
            {'$inc': {'likes': 1}}
        )
        return jsonify({"message": "Feedback liked!"}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to like feedback: {str(e)}"}), 500

# Dislike a feedback entry
@app.route('/api/feedback/<feedback_id>/dislike', methods=['POST'])
@api_login_required
def api_dislike_feedback(feedback_id):
    try:
        feedback = feedbacks_collection.find_one({'_id': ObjectId(feedback_id)})
    except:
        return jsonify({"error": "Invalid feedback ID"}), 400
    
    if not feedback:
        return jsonify({"error": "Feedback not found"}), 404
    
    existing_dislike = likes_dislikes_collection.find_one({
        'feedback_id': ObjectId(feedback_id), 
        'user_id': ObjectId(current_user.id)
    })

    if existing_dislike:
        return jsonify({"error": "You have already interacted with this feedback."}), 400

    dislike_data = {
        'feedback_id': ObjectId(feedback_id),
        'user_id': ObjectId(current_user.id),
        'like': False,
        'timestamp': datetime.utcnow()
    }
    
    try:
        likes_dislikes_collection.insert_one(dislike_data)
        feedbacks_collection.update_one(
            {'_id': ObjectId(feedback_id)},
            {'$inc': {'dislikes': 1}}
        )
        return jsonify({"message": "Feedback disliked!"}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to dislike feedback: {str(e)}"}), 500

# Submit anonymous feedback (no authentication required)
@app.route('/api/anonymous-feedback', methods=['POST'])
def api_anonymous_feedback():
    data = request.get_json()
    category = data.get('category')
    description = data.get('description')

    if not category or not description:
        return jsonify({"error": "Category and description are required."}), 400

    feedback_data = {
        'category': category,
        'description': description,
        'anonymous': True,
        'timestamp': datetime.utcnow(),
        'likes': 0,
        'dislikes': 0
    }

    try:
        feedbacks_collection.insert_one(feedback_data)
        return jsonify({"message": "Anonymous feedback submitted successfully!"}), 201
    except Exception as e:
        return jsonify({"error": f"Failed to submit anonymous feedback: {str(e)}"}), 500

# Promote a user to admin (only accessible by admins)
@app.route('/promote/<user_id>', methods=['POST'])
@api_login_required
def promote_user(user_id):
    if not current_user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    try:
        result = users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'is_admin': True}}
        )
        if result.matched_count == 0:
            return jsonify({"error": "User not found"}), 404
        return jsonify({"message": f"User has been promoted to admin."}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to promote user: {str(e)}"}), 500

# Demote a user from admin (only accessible by admins)
@app.route('/demote/<user_id>', methods=['POST'])
@api_login_required
def demote_user(user_id):
    if not current_user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    try:
        result = users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'is_admin': False}}
        )
        if result.matched_count == 0:
            return jsonify({"error": "User not found"}), 404
        return jsonify({"message": f"User has been demoted from admin."}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to demote user: {str(e)}"}), 500

# Delete a feedback entry (only owner or admin can delete)
@app.route('/api/feedback/<feedback_id>', methods=['DELETE'])
@api_login_required
def delete_feedback(feedback_id):
    try:
        feedback = feedbacks_collection.find_one({'_id': ObjectId(feedback_id)})
    except:
        return jsonify({"error": "Invalid feedback ID"}), 400
    
    if not feedback:
        return jsonify({"error": "Feedback not found"}), 404
    
    feedback_user_id = str(feedback.get('user_id', ''))
    if feedback_user_id != current_user.id and not current_user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    try:
        # Delete associated comments and likes first
        comments_collection.delete_many({'feedback_id': ObjectId(feedback_id)})
        likes_dislikes_collection.delete_many({'feedback_id': ObjectId(feedback_id)})
        feedbacks_collection.delete_one({'_id': ObjectId(feedback_id)})
        return jsonify({"message": "Feedback deleted successfully!"}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to delete feedback: {str(e)}"}), 500

# Delete a comment (only comment owner or admin can delete)
@app.route('/api/comment/<comment_id>', methods=['DELETE'])
@api_login_required
def delete_comment(comment_id):
    try:
        comment = comments_collection.find_one({'_id': ObjectId(comment_id)})
    except Exception as e:
        logging.error(f"Invalid comment ID: {str(e)}")
        return jsonify({"error": "Invalid comment ID"}), 400
    
    if not comment:
        return jsonify({"error": "Comment not found"}), 404
    
    comment_user_id = str(comment.get('user_id', ''))
    if comment_user_id != current_user.id and not current_user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    try:
        comments_collection.delete_one({'_id': ObjectId(comment_id)})
        return jsonify({"message": "Comment deleted successfully!"}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to delete comment: {str(e)}"}), 500

# Get user profile information
@app.route('/api/user/profile', methods=['GET'])
@api_login_required
def get_user_profile():
    user = current_user
    photo_filename = user._data.get('profile_photo_filename') if hasattr(user, '_data') else None
    profile_photo_url = user._data.get('profile_photo_url') if hasattr(user, '_data') else None
    if not profile_photo_url and photo_filename:
        profile_photo_url = url_for('static', filename=f'uploads/{photo_filename}', _external=True)

    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "is_admin": user.is_admin,
        "profile_photo_url": profile_photo_url
    }), 200

@app.route('/api/user/profile/photo', methods=['POST'])
@api_login_required
def upload_profile_photo():
    import uuid
    import base64
    try:
        image_data = None
        ext = None

        if request.is_json:
            data = request.get_json(silent=True) or {}
            image_base64 = data.get('image')
            filename = secure_filename(data.get('filename') or '')
            if not image_base64 or not filename:
                return jsonify({"error": "Image and filename are required"}), 400

            if not allowed_profile_image(filename):
                return jsonify({"error": "Invalid image type"}), 400

            ext = filename.rsplit('.', 1)[1].lower()
            if ',' in image_base64:
                image_base64 = image_base64.split(',', 1)[1]
            image_data = base64.b64decode(image_base64)
        else:
            photo = request.files.get('photo')
            if not photo or photo.filename == '':
                return jsonify({"error": "Photo file is required"}), 400

            if not allowed_profile_image(photo.filename):
                return jsonify({"error": "Invalid image type"}), 400

            filename = secure_filename(photo.filename)
            ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
            if not ext:
                return jsonify({"error": "Invalid filename"}), 400

        filename = f"profile_{current_user.id}_{uuid.uuid4().hex}.{ext}"
        filepath = os.path.abspath(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        upload_dir = os.path.abspath(app.config['UPLOAD_FOLDER'])
        if not filepath.startswith(upload_dir):
            return jsonify({"error": "Invalid file path"}), 400

        if request.is_json:
            with open(filepath, 'wb') as f:
                f.write(image_data)
        else:
            photo.save(filepath)

        profile_photo_url = url_for('static', filename=f'uploads/{filename}', _external=True)
        users_collection.update_one(
            {'_id': ObjectId(current_user.id)},
            {'$set': {
                'profile_photo_filename': filename,
                'profile_photo_url': profile_photo_url,
                'updated_at': datetime.utcnow()
            }}
        )

        return jsonify({
            "message": "Profile photo updated successfully",
            "profile_photo_url": profile_photo_url
        }), 200
    except Exception as e:
        logging.error("Failed to upload profile photo: %s", str(e))
        return jsonify({"error": f"Failed to upload profile photo: {str(e)}"}), 500

# Logout endpoint
@app.route('/api/logout', methods=['POST'])
@api_login_required
def logout():
    logout_user()
    return jsonify({"message": "Logged out successfully!"}), 200

# Get all users (only accessible by admin)
@app.route('/api/users', methods=['GET'])
@api_login_required
def get_all_users():
    if not current_user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    users = list(users_collection.find())
    users_list = [{
        "id": str(user['_id']),
        "username": user['username'],
        "email": user['email'],
        "is_admin": user.get('is_admin', False)
    } for user in users]

    return jsonify(users_list), 200

# Admin Analytics Dashboard
@app.route('/api/admin/analytics', methods=['GET'])
@api_login_required
def admin_analytics():
    if not current_user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        # Total feedback count
        total_feedback = feedbacks_collection.count_documents({})
        
        # Feedback by category
        category_pipeline = [
            {'$group': {'_id': '$category', 'count': {'$sum': 1}}}
        ]
        feedback_by_category = list(feedbacks_collection.aggregate(category_pipeline))
        category_stats = {item['_id']: item['count'] for item in feedback_by_category if item['_id']}
        
        # Feedback by date (last 7 days)
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        date_pipeline = [
            {'$match': {'timestamp': {'$gte': seven_days_ago}}},
            {'$group': {
                '_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$timestamp'}},
                'count': {'$sum': 1}
            }},
            {'$sort': {'_id': 1}}
        ]
        feedback_by_date = list(feedbacks_collection.aggregate(date_pipeline))
        date_stats = {item['_id']: item['count'] for item in feedback_by_date}
        
        # Total users count
        total_users = users_collection.count_documents({})
        
        # Total likes and dislikes
        likes_pipeline = [
            {'$group': {'_id': None, 'total_likes': {'$sum': '$likes'}, 'total_dislikes': {'$sum': '$dislikes'}}}
        ]
        likes_stats = list(feedbacks_collection.aggregate(likes_pipeline))
        total_likes = likes_stats[0]['total_likes'] if likes_stats else 0
        total_dislikes = likes_stats[0]['total_dislikes'] if likes_stats else 0
        
        # Anonymous vs identified feedback
        anonymous_count = feedbacks_collection.count_documents({'anonymous': True})
        identified_count = total_feedback - anonymous_count
        
        return jsonify({
            'total_feedback': total_feedback,
            'category_stats': category_stats,
            'date_stats': date_stats,
            'total_users': total_users,
            'total_likes': total_likes,
            'total_dislikes': total_dislikes,
            'anonymous_count': anonymous_count,
            'identified_count': identified_count
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to get analytics: {str(e)}"}), 500

# Get notifications for user
@app.route('/api/notifications', methods=['GET'])
@api_login_required
def get_notifications():
    try:
        user_id = ObjectId(current_user.id)
        notifications = []
        
        # Get user's feedback IDs
        user_feedbacks = list(feedbacks_collection.find({'user_id': user_id}))
        user_feedback_ids = [fb['_id'] for fb in user_feedbacks]
        
        # Get recent comments on user's feedback
        if user_feedback_ids:
            recent_comments = list(comments_collection.find(
                {'feedback_id': {'$in': user_feedback_ids}}
            ).sort('timestamp', -1).limit(10))
            
            for comment in recent_comments:
                notifications.append({
                    'type': 'comment',
                    'message': f'New comment on your feedback',
                    'timestamp': comment.get('timestamp').isoformat() if comment.get('timestamp') else None,
                    'feedback_id': str(comment.get('feedback_id'))
                })
        
        # Get recent likes/dislikes on user's feedback
        if user_feedback_ids:
            recent_likes = list(likes_dislikes_collection.find(
                {'feedback_id': {'$in': user_feedback_ids}}
            ).sort('timestamp', -1).limit(10))
            
            for like in recent_likes:
                notifications.append({
                    'type': 'like' if like.get('like') else 'dislike',
                    'message': f"{'Someone liked' if like.get('like') else 'Someone disliked'} your feedback",
                    'timestamp': like.get('timestamp').isoformat() if like.get('timestamp') else None,
                    'feedback_id': str(like.get('feedback_id'))
                })
        
        # Sort notifications by timestamp and limit to 20
        notifications.sort(key=lambda x: x['timestamp'] or '', reverse=True)
        notifications = notifications[:20]
        
        return jsonify({'notifications': notifications}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to get notifications: {str(e)}"}), 500

# ==================== SENTIMENT ANALYSIS ====================
# Simple sentiment analysis using keyword-based approach
# For production, consider using TextBlob, VADER, or ML models

POSITIVE_WORDS = [
    'good', 'great', 'excellent', 'amazing', 'wonderful', 'fantastic', 'awesome',
    'love', 'like', 'best', 'perfect', 'happy', 'thank', 'thanks', 'helpful',
    'improved', 'better', 'success', 'successful', 'efficient', 'effective',
    'satisfied', 'impressed', 'brilliant', 'outstanding', 'superb', 'nice'
]

NEGATIVE_WORDS = [
    'bad', 'terrible', 'awful', 'horrible', 'worst', 'hate', 'dislike',
    'poor', 'failed', 'failure', 'slow', 'broken', 'problem', 'issue', 'wrong',
    'complaint', 'angry', 'frustrated', 'disappointed', 'useless', 'waste',
    'expensive', 'dangerous', 'unsafe', 'corrupt', 'neglect', 'ignore'
]

def analyze_sentiment(text):
    """Analyze sentiment of text using keyword matching"""
    if not text:
        return {'sentiment': 'neutral', 'score': 0, 'confidence': 0}
    
    text_lower = text.lower()
    words = text_lower.split()
    
    positive_count = sum(1 for word in words if word in POSITIVE_WORDS)
    negative_count = sum(1 for word in words if word in NEGATIVE_WORDS)
    
    total = positive_count + negative_count
    
    if total == 0:
        return {'sentiment': 'neutral', 'score': 0, 'confidence': 0}
    
    score = (positive_count - negative_count) / total
    confidence = min(total / len(words) * 10, 1.0)  # Cap at 1.0
    
    if score > 0.2:
        sentiment = 'positive'
    elif score < -0.2:
        sentiment = 'negative'
    else:
        sentiment = 'neutral'
    
    return {
        'sentiment': sentiment,
        'score': round(score, 2),
        'confidence': round(confidence, 2),
        'positive_count': positive_count,
        'negative_count': negative_count
    }

@app.route('/api/feedback/<feedback_id>/analyze-sentiment', methods=['GET'])
@api_login_required
def analyze_feedback_sentiment(feedback_id):
    """Analyze sentiment of a specific feedback"""
    try:
        feedback = feedbacks_collection.find_one({'_id': ObjectId(feedback_id)})
        if not feedback:
            return jsonify({'error': 'Feedback not found'}), 404
        
        sentiment_result = analyze_sentiment(feedback.get('description', ''))
        return jsonify(sentiment_result), 200
    except Exception as e:
        return jsonify({'error': f'Failed to analyze sentiment: {str(e)}'}), 500

@app.route('/api/feedback/analyze-batch', methods=['POST'])
@api_login_required
def analyze_batch_sentiment():
    """Analyze sentiment for multiple feedbacks"""
    try:
        data = request.get_json()
        feedback_ids = data.get('feedback_ids', [])
        
        results = []
        for fb_id in feedback_ids:
            feedback = feedbacks_collection.find_one({'_id': ObjectId(fb_id)})
            if feedback:
                sentiment = analyze_sentiment(feedback.get('description', ''))
                results.append({
                    'feedback_id': str(feedback['_id']),
                    'category': feedback.get('category'),
                    'sentiment': sentiment
                })
        
        return jsonify({'results': results}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to analyze batch: {str(e)}'}), 500

# ==================== SENTIMENT ANALYTICS ====================
@app.route('/api/admin/sentiment-analytics', methods=['GET'])
@api_login_required
def get_sentiment_analytics():
    """Get sentiment analytics for admin dashboard"""
    try:
        if not current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        
        all_feedbacks = list(feedbacks_collection.find())
        
        sentiment_counts = {'positive': 0, 'negative': 0, 'neutral': 0}
        category_sentiment = {}
        
        for fb in all_feedbacks:
            sentiment = analyze_sentiment(fb.get('description', ''))
            sentiment_counts[sentiment['sentiment']] = sentiment_counts.get(sentiment['sentiment'], 0) + 1
            
            category = fb.get('category', 'Unknown')
            if category not in category_sentiment:
                category_sentiment[category] = {'positive': 0, 'negative': 0, 'neutral': 0}
            category_sentiment[category][sentiment['sentiment']] += 1
        
        return jsonify({
            'total_feedback': len(all_feedbacks),
            'sentiment_counts': sentiment_counts,
            'category_sentiment': category_sentiment,
            'average_score': sum(analyze_sentiment(fb.get('description', ''))['score'] for fb in all_feedbacks) / len(all_feedbacks) if all_feedbacks else 0
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to get sentiment analytics: {str(e)}'}), 500

# ==================== OAUTH2 CONFIGURATION ====================
# OAuth2 Configuration for Google and Facebook
# Set these in your .env file:
# GOOGLE_CLIENT_ID=your_google_client_id
# GOOGLE_CLIENT_SECRET=your_google_client_secret
# FACEBOOK_APP_ID=your_facebook_app_id
# FACEBOOK_APP_SECRET=your_facebook_secret

GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
FACEBOOK_APP_ID = os.getenv('FACEBOOK_APP_ID')
FACEBOOK_APP_SECRET = os.getenv('FACEBOOK_APP_SECRET')

# Google OAuth2
@app.route('/api/auth/google')
def google_auth():
    """Redirect to Google for OAuth2 authentication"""
    if not GOOGLE_CLIENT_ID:
        return jsonify({'error': 'Google OAuth not configured'}), 400
    
    import urllib.parse
    # Generate cryptographically secure state parameter
    state = secrets.token_urlsafe(32)
    # Store state in session for verification (in production, use server-side state storage)
    session['oauth_state'] = state
    session.modified = True
    
    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': os.getenv('GOOGLE_REDIRECT_URI', 'http://localhost:5000/api/auth/google/callback'),
        'response_type': 'code',
        'scope': 'openid email profile',
        'access_type': 'offline',
        'state': state
    }
    google_auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(params)}"
    return jsonify({'auth_url': google_auth_url}), 200

@app.route('/api/auth/google/callback', methods=['GET'])
def google_callback():
    """Handle Google OAuth2 callback"""
    code = request.args.get('code')
    state = request.args.get('state')
    
    # Verify state parameter to prevent CSRF attacks
    stored_state = session.get('oauth_state')
    if not state or state != stored_state:
        return jsonify({'error': 'Invalid state parameter - possible CSRF attack'}), 400
    
    if not code or not GOOGLE_CLIENT_ID:
        return jsonify({'error': 'Authentication failed'}), 400
    
    # Clear state from session after verification
    session.pop('oauth_state', None)
    
    # In production, exchange code for tokens and get user info
    # This is a simplified version
    return jsonify({
        'message': 'Google OAuth callback received. Complete token exchange implementation needed.',
        'code': code
    }), 200

# Facebook OAuth2
@app.route('/api/auth/facebook')
def facebook_auth():
    """Redirect to Facebook for OAuth2 authentication"""
    if not FACEBOOK_APP_ID:
        return jsonify({'error': 'Facebook OAuth not configured'}), 400
    
    import urllib.parse
    # Generate cryptographically secure state parameter
    state = secrets.token_urlsafe(32)
    # Store state in session for verification
    session['oauth_state'] = state
    session.modified = True
    
    params = {
        'client_id': FACEBOOK_APP_ID,
        'redirect_uri': os.getenv('FACEBOOK_REDIRECT_URI', 'http://localhost:5000/api/auth/facebook/callback'),
        'state': state,
        'scope': 'email,public_profile'
    }
    facebook_auth_url = f"https://www.facebook.com/v18.0/dialog/oauth?{urllib.parse.urlencode(params)}"
    return jsonify({'auth_url': facebook_auth_url}), 200

@app.route('/api/auth/facebook/callback', methods=['GET'])
def facebook_callback():
    """Handle Facebook OAuth2 callback"""
    code = request.args.get('code')
    state = request.args.get('state')
    
    # Verify state parameter to prevent CSRF attacks
    stored_state = session.get('oauth_state')
    if not state or state != stored_state:
        return jsonify({'error': 'Invalid state parameter - possible CSRF attack'}), 400
    
    if not code or not FACEBOOK_APP_ID:
        return jsonify({'error': 'Authentication failed'}), 400
    
    # Clear state from session after verification
    session.pop('oauth_state', None)
    
    # In production, exchange code for access token and get user info
    return jsonify({
        'message': 'Facebook OAuth callback received. Complete token exchange implementation needed.',
        'code': code
    }), 200

# OAuth Status endpoint
@app.route('/api/auth/oauth-status', methods=['GET'])
def oauth_status():
    """Check which OAuth providers are configured"""
    return jsonify({
        'google_configured': bool(GOOGLE_CLIENT_ID),
        'facebook_configured': bool(FACEBOOK_APP_ID),
        'google_auth_url': '/api/auth/google' if GOOGLE_CLIENT_ID else None,
        'facebook_auth_url': '/api/auth/facebook' if FACEBOOK_APP_ID else None
    }), 200

# ==================== GOVERNMENT PROJECTS ====================
PROJECT_STATUSES = ['Planning', 'In Progress', 'On Hold', 'Completed', 'Cancelled']
PROJECT_CATEGORIES = ['Infrastructure', 'Health', 'Education', 'Agriculture', 'Security', 'Other']

@app.route('/api/projects', methods=['GET'])
@api_login_required
def get_projects():
    """Get all projects (with optional filtering)"""
    try:
        status = request.args.get('status')
        category = request.args.get('category')
        
        query = {}
        if status:
            query['status'] = status
        if category:
            query['category'] = category
        
        projects = list(projects_collection.find(query).sort('created_at', -1))
        
        # Convert ObjectId to string
        for project in projects:
            project['_id'] = str(project['_id'])
            project['created_at'] = project.get('created_at').isoformat() if project.get('created_at') else None
            project['updated_at'] = project.get('updated_at').isoformat() if project.get('updated_at') else None
        
        return jsonify({'projects': projects}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to get projects: {str(e)}'}), 500

@app.route('/api/projects/<project_id>', methods=['GET'])
@api_login_required
def get_project(project_id):
    """Get a specific project by ID"""
    try:
        project = projects_collection.find_one({'_id': ObjectId(project_id)})
        if not project:
            return jsonify({'error': 'Project not found'}), 404
        
        project['_id'] = str(project['_id'])
        project['created_at'] = project.get('created_at').isoformat() if project.get('created_at') else None
        project['updated_at'] = project.get('updated_at').isoformat() if project.get('updated_at') else None
        
        return jsonify({'project': project}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to get project: {str(e)}'}), 500

@app.route('/api/projects', methods=['POST'])
@api_login_required
def create_project():
    """Create a new project (admin only)"""
    try:
        if not current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        
        data = request.get_json()
        
        if not data.get('name') or not data.get('description') or not data.get('category'):
            return jsonify({'error': 'Name, description, and category are required'}), 400
        
        project = {
            'name': data['name'],
            'description': data['description'],
            'category': data['category'],
            'status': data.get('status', 'Planning'),
            'budget': data.get('budget', 0),
            'location': data.get('location', ''),
            'start_date': data.get('start_date'),
            'end_date': data.get('end_date'),
            'created_by': current_user.id,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'progress': 0,
            'milestones': data.get('milestones', [])
        }
        
        result = projects_collection.insert_one(project)
        project['_id'] = str(result.inserted_id)
        project['created_at'] = project['created_at'].isoformat()
        project['updated_at'] = project['updated_at'].isoformat()
        
        return jsonify({'message': 'Project created successfully', 'project': project}), 201
    except Exception as e:
        return jsonify({'error': f'Failed to create project: {str(e)}'}), 500

@app.route('/api/projects/<project_id>', methods=['PUT'])
@api_login_required
def update_project(project_id):
    """Update a project (admin only)"""
    try:
        if not current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        
        data = request.get_json()
        
        update_data = {key: value for key, value in data.items() 
                       if key in ['name', 'description', 'category', 'status', 'budget', 
                                 'location', 'start_date', 'end_date', 'progress', 'milestones']}
        update_data['updated_at'] = datetime.utcnow()
        
        result = projects_collection.update_one(
            {'_id': ObjectId(project_id)},
            {'$set': update_data}
        )
        
        if result.matched_count == 0:
            return jsonify({'error': 'Project not found'}), 404
        
        return jsonify({'message': 'Project updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to update project: {str(e)}'}), 500

@app.route('/api/projects/<project_id>', methods=['DELETE'])
@api_login_required
def delete_project(project_id):
    """Delete a project (admin only)"""
    try:
        if not current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        
        result = projects_collection.delete_one({'_id': ObjectId(project_id)})
        
        if result.deleted_count == 0:
            return jsonify({'error': 'Project not found'}), 404
        
        return jsonify({'message': 'Project deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to delete project: {str(e)}'}), 500

@app.route('/api/projects/<project_id>/progress', methods=['POST'])
@api_login_required
def update_project_progress(project_id):
    """Update project progress (admin only)"""
    try:
        if not current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        
        data = request.get_json()
        progress = data.get('progress', 0)
        
        if not 0 <= progress <= 100:
            return jsonify({'error': 'Progress must be between 0 and 100'}), 400
        
        result = projects_collection.update_one(
            {'_id': ObjectId(project_id)},
            {'$set': {'progress': progress, 'updated_at': datetime.utcnow()}}
        )
        
        if result.matched_count == 0:
            return jsonify({'error': 'Project not found'}), 404
        
        return jsonify({'message': 'Progress updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to update progress: {str(e)}'}), 500

@app.route('/api/projects/stats', methods=['GET'])
@api_login_required
def get_project_stats():
    """Get project statistics (admin)"""
    try:
        if not current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        
        total = projects_collection.count_documents({})
        
        status_counts = {}
        for status in PROJECT_STATUSES:
            status_counts[status] = projects_collection.count_documents({'status': status})
        
        category_counts = {}
        for category in PROJECT_CATEGORIES:
            category_counts[category] = projects_collection.count_documents({'category': category})
        
        # Calculate average progress
        projects = list(projects_collection.find({}, {'progress': 1}))
        avg_progress = sum(p.get('progress', 0) for p in projects) / total if total > 0 else 0
        
        return jsonify({
            'total_projects': total,
            'by_status': status_counts,
            'by_category': category_counts,
            'average_progress': round(avg_progress, 2)
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to get stats: {str(e)}'}), 500

# ==================== PASSWORD RESET ====================
import uuid
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def generate_reset_token():
    """Generate a unique password reset token"""
    return str(uuid.uuid4())

def is_production_env():
    return os.getenv('FLASK_ENV') == 'production'

def get_reset_link(token):
    frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000').rstrip('/')
    return f"{frontend_url}/reset-password/{token}"

def send_reset_email(email, token):
    """Send password reset email"""
    try:
        if app.config.get('MAIL_USE_AUTH', True) and (
            not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD')
        ):
            logging.warning('Mail authentication is enabled but MAIL_USERNAME/MAIL_PASSWORD are missing')
            return False
        
        msg = MIMEMultipart()
        msg['From'] = app.config.get('MAIL_DEFAULT_SENDER')
        msg['To'] = email
        msg['Subject'] = 'Password Reset - CMFS Citizen Feedback'
        
        reset_link = get_reset_link(token)
        body = f"""
        <html>
        <body>
            <h2>Password Reset Request</h2>
            <p>You requested a password reset for your CMFS Citizen Feedback account.</p>
            <p>Click the link below to reset your password:</p>
            <p><a href="{reset_link}" style="background-color: #006600; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
            <p>Or copy this link: {reset_link}</p>
            <p><strong>This link will expire in 1 hour.</strong></p>
            <p>If you didn't request this, please ignore this email.</p>
            <br>
            <p>Best regards,<br>CMFS Team</p>
        </body>
        </html>
        """
        msg.attach(MIMEText(body, 'html'))
        
        if app.config.get('MAIL_USE_SSL', False):
            server = smtplib.SMTP_SSL(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        else:
            server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
            if app.config.get('MAIL_USE_TLS', True):
                server.starttls()

        if app.config.get('MAIL_USE_AUTH', True):
            mail_username = (app.config.get('MAIL_USERNAME') or '').strip()
            # Gmail app passwords are often copied with spaces like "abcd efgh ...".
            mail_password = (app.config.get('MAIL_PASSWORD') or '').replace(' ', '').strip()
            server.login(mail_username, mail_password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        logging.error(f'Failed to send reset email: {str(e)}')
        return False

@app.route('/api/password-reset/request', methods=['POST'])
def request_password_reset():
    """Request a password reset"""
    try:
        data = request.get_json(silent=True) or {}
        email = (data.get('email') or '').strip().lower()
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        user = users_collection.find_one({'email': {'$regex': f'^{email}$', '$options': 'i'}})
        
        # Always return success to prevent email enumeration
        if user:
            # Generate and store token
            token = generate_reset_token()
            expires = datetime.utcnow() + timedelta(hours=1)
            
            password_reset_tokens_collection.update_one(
                {'user_id': user['_id']},
                {
                    '$set': {
                        'token': token,
                        'expires': expires,
                        'used': False
                    },
                    '$inc': {'attempts': 1}
                },
                upsert=True
            )
            
            # Send email (log in development)
            email_sent = send_reset_email(email, token)
            logging.info(f'Password reset token generated for {email}, email sent: {email_sent}')

        return jsonify({
            'message': 'If an account with that email exists, a password reset link has been sent.'
        }), 200
    except Exception as e:
        logging.error(f'Password reset request error: {str(e)}')
        return jsonify({'error': 'Failed to process request'}), 500

@app.route('/api/password-reset/verify/<token>', methods=['GET'])
def verify_reset_token(token):
    """Verify if a password reset token is valid"""
    try:
        token = (token or '').strip()
        if not token:
            return jsonify({'error': 'Invalid token'}), 400

        token_data = password_reset_tokens_collection.find_one({
            'token': token,
            'used': False,
            'expires': {'$gt': datetime.utcnow()}
        })
        
        if not token_data:
            return jsonify({'error': 'Invalid or expired token'}), 400
        
        return jsonify({
            'valid': True,
            'message': 'Token is valid'
        }), 200
    except Exception as e:
        return jsonify({'error': 'Failed to verify token'}), 500

@app.route('/api/password-reset/reset', methods=['POST'])
def reset_password():
    """Reset password using token"""
    try:
        data = request.get_json(silent=True) or {}
        token = (data.get('token') or '').strip()
        new_password = (data.get('new_password') or '').strip()
        
        if not token or not new_password:
            return jsonify({'error': 'Token and new password are required'}), 400
        
        if len(new_password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        # Find valid token
        token_data = password_reset_tokens_collection.find_one({
            'token': token,
            'used': False,
            'expires': {'$gt': datetime.utcnow()}
        })
        
        if not token_data:
            return jsonify({'error': 'Invalid or expired token'}), 400
        
        # Update user password
        user_id = token_data['user_id']
        hashed_password = generate_password_hash(new_password)
        
        user_update = users_collection.update_one(
            {'_id': user_id},
            {'$set': {'password': hashed_password}}
        )
        if user_update.matched_count == 0:
            return jsonify({'error': 'User account not found'}), 404
        
        # Mark token as used
        password_reset_tokens_collection.update_one(
            {'_id': token_data['_id']},
            {'$set': {'used': True, 'used_at': datetime.utcnow()}}
        )
        
        return jsonify({
            'message': 'Password reset successful! You can now login with your new password.'
        }), 200
    except Exception as e:
        logging.error(f'Password reset error: {str(e)}')
        return jsonify({'error': 'Failed to reset password'}), 500

# ==================== MOBILE APP API (JWT) ====================
# Note: JWT configuration and decorators are defined earlier in the file

@app.route('/api/mobile/login', methods=['POST'])
def mobile_login():
    """Mobile login endpoint - returns JWT token"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        user = users_collection.find_one({'username': username})
        
        if not user or not check_password_hash(user.get('password', ''), password):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        user_data = {
            'id': str(user['_id']),
            'username': user['username'],
            'email': user['email'],
            'is_admin': user.get('is_admin', False)
        }
        
        token = create_jwt_token(user_data)
        
        return jsonify({
            'success': True,
            'token': token,
            'user': user_data,
            'token_type': 'Bearer',
            'expires_in': JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }), 200
    except Exception as e:
        return jsonify({'error': f'Login failed: {str(e)}'}), 500

@app.route('/api/mobile/register', methods=['POST'])
def mobile_register():
    """Mobile registration endpoint - returns JWT token"""
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if not username or not email or not password:
            return jsonify({'error': 'All fields are required'}), 400
        
        # Check if user exists
        if users_collection.find_one({'username': username}):
            return jsonify({'error': 'Username already exists'}), 400
        
        if users_collection.find_one({'email': email}):
            return jsonify({'error': 'Email already exists'}), 400
        
        hashed_password = generate_password_hash(password)
        
        new_user = {
            'username': username,
            'email': email,
            'password': hashed_password,
            'is_admin': False,
            'created_at': datetime.utcnow()
        }
        
        result = users_collection.insert_one(new_user)
        user_id = str(result.inserted_id)
        
        user_data = {
            'id': user_id,
            'username': username,
            'email': email,
            'is_admin': False
        }
        
        token = create_jwt_token(user_data)
        
        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'token': token,
            'user': user_data,
            'token_type': 'Bearer',
            'expires_in': JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }), 201
    except Exception as e:
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500

@app.route('/api/mobile/feedback', methods=['GET'])
@mobile_login_required
def mobile_get_feedback():
    """Mobile endpoint - get all feedback (mobile-optimized)"""
    try:
        # Validate and bound pagination parameters
        try:
            page = max(1, int(request.args.get('page', 1)))
            limit = min(100, max(1, int(request.args.get('limit', 20))))
        except (ValueError, TypeError):
            page = 1
            limit = 20
        skip = (page - 1) * limit
        
        feedbacks = list(feedbacks_collection.find()
                       .sort('created_at', -1)
                       .skip(skip)
                       .limit(limit))
        
        total = feedbacks_collection.count_documents({})
        
        result = []
        for fb in feedbacks:
            result.append({
                'id': str(fb['_id']),
                'category': fb.get('category'),
                'description': fb.get('description'),
                'anonymous': fb.get('anonymous', False),
                'likes': fb.get('likes', 0),
                'dislikes': fb.get('dislikes', 0),
                'comments_count': comments_collection.count_documents({'feedback_id': fb['_id']}),
                'image_url': fb.get('image_url'),
                'created_at': fb.get('created_at').isoformat() if fb.get('created_at') else None
            })
        
        return jsonify({
            'success': True,
            'data': result,
            'pagination': {
                'page': page,
                'limit': limit,
                'total': total,
                'pages': (total + limit - 1) // limit
            }
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to get feedback: {str(e)}'}), 500

@app.route('/api/mobile/feedback', methods=['POST'])
@mobile_login_required
def mobile_submit_feedback():
    """Mobile endpoint - submit feedback"""
    try:
        data = request.get_json()
        
        feedback = {
            'user_id': ObjectId(request.mobile_user['user_id']),
            'category': data.get('category'),
            'description': data.get('description'),
            'anonymous': data.get('anonymous', False),
            'likes': 0,
            'dislikes': 0,
            'created_at': datetime.utcnow()
        }
        
        result = feedbacks_collection.insert_one(feedback)
        
        return jsonify({
            'success': True,
            'message': 'Feedback submitted successfully',
            'feedback_id': str(result.inserted_id)
        }), 201
    except Exception as e:
        return jsonify({'error': f'Failed to submit feedback: {str(e)}'}), 500

@app.route('/api/mobile/projects', methods=['GET'])
@mobile_login_required
def mobile_get_projects():
    """Mobile endpoint - get all projects (mobile-optimized)"""
    try:
        projects = list(projects_collection.find()
                       .sort('created_at', -1))
        
        result = []
        for proj in projects:
            result.append({
                'id': str(proj['_id']),
                'name': proj.get('name'),
                'description': proj.get('description'),
                'category': proj.get('category'),
                'status': proj.get('status'),
                'progress': proj.get('progress', 0),
                'location': proj.get('location'),
                'budget': proj.get('budget', 0),
                'start_date': proj.get('start_date'),
                'end_date': proj.get('end_date'),
                'created_at': proj.get('created_at').isoformat() if proj.get('created_at') else None
            })
        
        return jsonify({
            'success': True,
            'data': result
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to get projects: {str(e)}'}), 500

@app.route('/api/mobile/profile', methods=['GET'])
@mobile_login_required
def mobile_get_profile():
    """Mobile endpoint - get user profile"""
    try:
        user = users_collection.find_one({'_id': ObjectId(request.mobile_user['user_id'])})
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get user's feedback count
        feedback_count = feedbacks_collection.count_documents({'user_id': ObjectId(request.mobile_user['user_id'])})
        
        return jsonify({
            'success': True,
            'data': {
                'id': str(user['_id']),
                'username': user['username'],
                'email': user['email'],
                'is_admin': user.get('is_admin', False),
                'feedback_count': feedback_count,
                'created_at': user.get('created_at').isoformat() if user.get('created_at') else None
            }
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to get profile: {str(e)}'}), 500

@app.route('/api/mobile/token/refresh', methods=['POST'])
@mobile_login_required
def mobile_refresh_token():
    """Mobile endpoint - refresh JWT token"""
    try:
        user_data = {
            'id': request.mobile_user['user_id'],
            'username': request.mobile_user['username'],
            'email': request.mobile_user['email'],
            'is_admin': request.mobile_user.get('is_admin', False)
        }
        
        token = create_jwt_token(user_data)
        
        return jsonify({
            'success': True,
            'token': token,
            'token_type': 'Bearer',
            'expires_in': JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to refresh token: {str(e)}'}), 500

# ==================== CHAT/MESSAGING ====================

@app.route('/api/conversations', methods=['GET'])
@api_login_required
def get_conversations():
    """Get all conversations for current user"""
    try:
        user_id = ObjectId(current_user.id)
        
        # Get conversations where user is participant
        conversations = list(conversations_collection.find({
            'participants': user_id
        }).sort('updated_at', -1))
        
        result = []
        for conv in conversations:
            # Get other participant info
            other_participants = [p for p in conv['participants'] if p != user_id]
            other_user = None
            if other_participants:
                other_user = users_collection.find_one({'_id': other_participants[0]})
            
            # Get last message
            last_message = None
            try:
                last_message = messages_collection.find_one(
                    {'conversation_id': conv['_id']},
                    sort=[('created_at', -1)]
                )
            except Exception as e:
                logging.error(f"Error getting last message: {str(e)}")
            
            # Get unread count
            unread_count = messages_collection.count_documents({
                'conversation_id': conv['_id'],
                'recipient_id': user_id,
                'read': False
            })
            
            result.append({
                'id': str(conv['_id']),
                'other_user': {
                    'id': str(other_user['_id']),
                    'username': other_user['username']
                } if other_user else None,
                'last_message': last_message['content'][:50] + '...' if last_message and 'content' in last_message else None,
                'last_message_time': last_message['created_at'].isoformat() if last_message and 'created_at' in last_message else None,
                'unread_count': unread_count,
                'updated_at': conv.get('updated_at').isoformat() if conv.get('updated_at') else None
            })
        
        return jsonify({'conversations': result}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to get conversations: {str(e)}'}), 500

@app.route('/api/conversations/<conversation_id>/messages', methods=['GET'])
@api_login_required
def get_messages(conversation_id):
    """Get all messages in a conversation"""
    try:
        user_id = ObjectId(current_user.id)
        
        # Verify user is part of conversation
        conversation = conversations_collection.find_one({
            '_id': ObjectId(conversation_id),
            'participants': user_id
        })
        
        if not conversation:
            return jsonify({'error': 'Conversation not found'}), 404
        
        # Get messages with validated pagination
        try:
            page = max(1, int(request.args.get('page', 1)))
            limit = min(100, max(1, int(request.args.get('limit', 50))))
        except (ValueError, TypeError):
            page = 1
            limit = 50
        skip = (page - 1) * limit
        
        messages = list(messages_collection.find({
            'conversation_id': ObjectId(conversation_id)
        }).sort('created_at', -1).skip(skip).limit(limit))
        
        unread_messages = list(messages_collection.find({
            'conversation_id': ObjectId(conversation_id),
            'recipient_id': user_id,
            'read': False
        }, {'_id': 1, 'sender_id': 1}))

        # Mark messages as read
        if unread_messages:
            unread_ids = [msg['_id'] for msg in unread_messages]
            now = datetime.utcnow()
            messages_collection.update_many(
                {'_id': {'$in': unread_ids}},
                {'$set': {'read': True, 'read_at': now, 'delivered': True, 'delivered_at': now}}
            )
            for msg in unread_messages:
                socketio.emit('message_status', {
                    'message_id': str(msg['_id']),
                    'conversation_id': conversation_id,
                    'delivered': True,
                    'read': True,
                    'delivered_at': now.isoformat(),
                    'read_at': now.isoformat()
                }, room=f"user_{str(msg['sender_id'])}")
        
        result = []
        for msg in messages:
            result.append({
                'id': str(msg['_id']),
                'sender_id': str(msg['sender_id']),
                'content': msg['content'],
                'conversation_id': str(msg['conversation_id']),
                'recipient_id': str(msg.get('recipient_id')) if msg.get('recipient_id') else None,
                'delivered': msg.get('delivered', msg.get('read', False)),
                'delivered_at': msg.get('delivered_at').isoformat() if msg.get('delivered_at') else None,
                'read': msg.get('read', False),
                'read_at': msg.get('read_at').isoformat() if msg.get('read_at') else None,
                'created_at': msg['created_at'].isoformat()
            })
        
        return jsonify({'messages': result}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to get messages: {str(e)}'}), 500

@app.route('/api/conversations/<conversation_id>/messages', methods=['POST'])
@api_login_required
def send_message(conversation_id):
    """Send a message in a conversation"""
    try:
        user_id = ObjectId(current_user.id)
        data = request.get_json()
        content = data.get('content')
        
        if not content:
            return jsonify({'error': 'Message content is required'}), 400
        
        # Verify user is part of conversation
        conversation = conversations_collection.find_one({
            '_id': ObjectId(conversation_id),
            'participants': user_id
        })
        
        if not conversation:
            return jsonify({'error': 'Conversation not found'}), 404
        
        # Determine recipient
        recipient_id = [p for p in conversation['participants'] if p != user_id][0]
        recipient_online = is_user_connected(str(recipient_id))
        now = datetime.utcnow()
        
        # Create message
        message = {
            'conversation_id': ObjectId(conversation_id),
            'sender_id': user_id,
            'recipient_id': recipient_id,
            'content': content,
            'delivered': recipient_online,
            'delivered_at': now if recipient_online else None,
            'read': False,
            'read_at': None,
            'created_at': now
        }
        
        result = messages_collection.insert_one(message)
        
        # Update conversation
        conversations_collection.update_one(
            {'_id': ObjectId(conversation_id)},
            {'$set': {'updated_at': now}}
        )

        message_payload = {
            'id': str(result.inserted_id),
            'conversation_id': conversation_id,
            'sender_id': str(user_id),
            'recipient_id': str(recipient_id),
            'content': content,
            'delivered': recipient_online,
            'delivered_at': now.isoformat() if recipient_online else None,
            'read': False,
            'read_at': None,
            'created_at': now.isoformat()
        }
        socketio.emit('new_message', message_payload, room=f"user_{str(recipient_id)}")

        socketio.emit('notification', {
            'id': f"msg-{str(result.inserted_id)}",
            'type': 'message',
            'title': 'New Message',
            'message': f'New message from {current_user.username}',
            'conversation_id': conversation_id,
            'timestamp': now.isoformat()
        }, room=f"user_{str(recipient_id)}")

        socketio.emit('message_status', {
            'message_id': str(result.inserted_id),
            'conversation_id': conversation_id,
            'delivered': recipient_online,
            'read': False,
            'delivered_at': now.isoformat() if recipient_online else None,
            'read_at': None
        }, room=f"user_{str(user_id)}")
        
        return jsonify({
            'message': 'Message sent successfully',
            'message_id': str(result.inserted_id)
        }), 201
    except Exception as e:
        return jsonify({'error': f'Failed to send message: {str(e)}'}), 500

@app.route('/api/conversations/start', methods=['POST'])
@api_login_required
def start_conversation():
    """Start a new conversation with another user"""
    try:
        user_id = ObjectId(current_user.id)
        data = request.get_json()
        recipient_id = data.get('recipient_id')
        
        if not recipient_id:
            return jsonify({'error': 'Recipient ID is required'}), 400
        
        recipient = users_collection.find_one({'_id': ObjectId(recipient_id)})
        if not recipient:
            return jsonify({'error': 'Recipient not found'}), 404
        
        # Check if conversation already exists
        existing = conversations_collection.find_one({
            'participants': {'$all': [user_id, ObjectId(recipient_id)], '$size': 2}
        })
        
        if existing:
            return jsonify({
                'conversation_id': str(existing['_id']),
                'exists': True
            }), 200
        
        # Create new conversation
        conversation = {
            'participants': [user_id, ObjectId(recipient_id)],
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        
        result = conversations_collection.insert_one(conversation)
        
        return jsonify({
            'conversation_id': str(result.inserted_id),
            'exists': False
        }), 201
    except Exception as e:
        return jsonify({'error': f'Failed to start conversation: {str(e)}'}), 500

@app.route('/api/users/search', methods=['GET'])
@api_login_required
def search_users():
    """Search for users to start a conversation with"""
    try:
        import re
        query = request.args.get('q', '')
        
        if len(query) < 2:
            return jsonify({'users': []}), 200
        
        # Sanitize query to prevent NoSQL injection - escape regex special characters
        safe_query = re.escape(query)
        
        users = list(users_collection.find(
            {'username': {'$regex': f'^{safe_query}', '$options': 'i'}},
            {'password': 0}
        ).limit(10))
        
        result = []
        for user in users:
            if str(user['_id']) != current_user.id:
                result.append({
                    'id': str(user['_id']),
                    'username': user['username'],
                    'email': user['email']
                })
        
        return jsonify({'users': result}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to search users: {str(e)}'}), 500

# Main entry point
if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)

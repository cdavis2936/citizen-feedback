import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from wtforms import StringField, PasswordField, BooleanField, TextAreaField, SubmitField, FileField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo
from dotenv import load_dotenv
from flask_migrate import Migrate
from sqlalchemy.orm import joinedload
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_cors import CORS
from datetime import datetime
from flask_login import current_user

# Load environment variables from the .env file
load_dotenv()

# Flask app setup
app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://localhost:3000"])

# Define base directory
basedir = os.path.abspath(os.path.dirname(__file__))

# Configurations
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///citizen_feedback.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['CORS_HEADERS'] = 'Content-Type'

# Upload folder and allowed extensions
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp', 'svg'}

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Set this line to match your actual login endpoint
login_manager.login_view = 'api_login'

# User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) if user_id else None

# Allowed file checker
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    feedbacks = db.relationship('Feedback', backref='user', lazy=True)
    comments = db.relationship('Comment', back_populates='user', lazy=True)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    anonymous = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    photo_filename = db.Column(db.String(255), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    comments = db.relationship('Comment', backref='feedback', lazy=True)
    likes = db.Column(db.Integer, default=0)
    dislikes = db.Column(db.Integer, default=0)
    image_url = db.Column(db.String(255), nullable=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    feedback_id = db.Column(db.Integer, db.ForeignKey('feedback.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', back_populates='comments')

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
    photo = FileField("Upload Photo")
    submit = SubmitField("Submit")

class CommentForm(FlaskForm):
    content = TextAreaField('Comment', validators=[DataRequired()])
    submit = SubmitField('Submit Comment')

class FeedbackFilterForm(FlaskForm):
    category = SelectField('Category', choices=[('All', 'All'), ('Infrastructure', 'Infrastructure'), ('Security', 'Security'), ('Health', 'Health'), ('Education', 'Education')])
    submit = SubmitField('Filter')

# Admin view
class AdminModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))

# Admin panel
admin = Admin(app, name='Feedback Admin', template_mode='bootstrap3')
admin.add_view(AdminModelView(User, db.session))
admin.add_view(AdminModelView(Feedback, db.session))
admin.add_view(AdminModelView(Comment, db.session))

# Pagination
def paginate(query, page_size=10):
    page = request.args.get('page', 1, type=int)
    return query.paginate(page=page, per_page=page_size, error_out=False)

# Routes
@app.route('/feedback_dashboard', methods=['GET', 'POST'])
@login_required
def feedback_dashboard():
    form = FeedbackFilterForm()
    page = request.args.get('page', 1, type=int)
    feedback_query = Feedback.query.order_by(Feedback.timestamp.desc())

    if form.validate_on_submit():
        category = form.category.data
        if category and category != 'All':
            feedback_query = feedback_query.filter_by(category=category)
    elif request.args.get('category'):
        category = request.args.get('category')
        if category and category != 'All':
            feedback_query = feedback_query.filter_by(category=category)

    pagination = feedback_query.paginate(page=page, per_page=10, error_out=False)
    return render_template('feedback_dashboard.html', feedback_list=pagination.items, pagination=pagination, form=form)

@app.route('/like_feedback/<int:feedback_id>', methods=['POST'])
@login_required
def like_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    feedback.likes = (feedback.likes or 0) + 1
    db.session.commit()
    flash('Feedback liked!', 'success')
    return redirect(url_for('feedback_dashboard'))

# API Routes
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({"error": "Username, email, and password are required."}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 400

    hashed_password = generate_password_hash(password)
    user = User(username=username, email=email, password=hashed_password)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "Registration successful!"}), 201


@app.route('/api/login', methods=['POST'])
def api_login():
    if request.method == 'POST':
        data = request.get_json()

        # Ensure the required fields are present
        if not data.get('username') or not data.get('password'):
            return jsonify({"error": "Username and password are required"}), 400

        username = data.get('username')
        password = data.get('password')

        # Fetch user from the database
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return jsonify({"message": "Login successful!"}), 200

        return jsonify({"error": "Invalid username or password"}), 401

    return jsonify({"message": "Please log in by sending a POST request with your credentials."}), 200

def unauthorized():
    return jsonify({"error": "Unauthorized"}), 401

# Feedback API (Updated)
@app.route('/api/feedback', methods=['POST'])
def api_feedback():
    # Check if the user is authenticated
    if not current_user.is_authenticated:
        return jsonify({"error": "User must be logged in to submit feedback."}), 401

    # Ensure the form has the necessary fields
    category = request.form.get('category')
    description = request.form.get('description')
    anonymous = request.form.get('anonymous', 'false').lower() == 'true'
    
    if not category or not description:
        return jsonify({"error": "Category and description are required."}), 400

    # Handle file upload
    photo = request.files.get('photo')
    filename = None

    if photo:
        if photo.filename == '':
            return jsonify({"error": "No selected file"}), 400

        if allowed_file(photo.filename):
            filename = secure_filename(photo.filename)
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            return jsonify({"error": "Invalid file type"}), 400
    else:
        filename = None  # If no photo, set filename to None

    # Create feedback entry
    new_feedback = Feedback(
        category=category,
        description=description,
        anonymous=anonymous,
        photo_filename=filename,  # Store the filename in the database
        timestamp=datetime.utcnow(),
        user_id=current_user.id,  # If user is authenticated, use their id
        likes=0,
        dislikes=0
    )

    try:
        db.session.add(new_feedback)
        db.session.commit()
        return jsonify({"message": "Feedback submitted successfully!"}), 201
    except Exception as e:
        db.session.rollback()  # Rollback in case of failure
        return jsonify({"error": f"Failed to submit feedback: {str(e)}"}), 500


@app.route('/api/feedback', methods=['GET'])
def api_get_feedback():
    feedback = Feedback.query.order_by(Feedback.timestamp.desc()).all()
    feedback_list = [{
        'id': fb.id,
        'category': fb.category,
        'description': fb.description,
        'likes': fb.likes,
        'timestamp': fb.timestamp.isoformat()
    } for fb in feedback]
    return jsonify(feedback_list), 200

@app.route('/api/feedback/<int:feedback_id>/like', methods=['POST'])
@login_required
def api_like_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    feedback.likes += 1
    db.session.commit()
    return jsonify({"message": "Feedback liked!"}), 200

# Run the app
if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)
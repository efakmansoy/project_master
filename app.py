import os
import uuid
import json
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash, session, make_response, jsonify
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime, date as DDate, timedelta, timezone
from email_validator import validate_email, EmailNotValidError
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_apscheduler import APScheduler
from functools import wraps
from itsdangerous import URLSafeTimedSerializer
from weasyprint import HTML
import google.generativeai as genai
from PIL import Image
import io

# --- Gemini API Configuration ---
# API anahtarını önce ortam değişkeninden almayı dene
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

# Eğer ortam değişkeni yoksa, credentials.json dosyasından okumayı dene
if not GEMINI_API_KEY:
    try:
        with open("credentials.json", 'r') as f:
            credentials = json.load(f)
            GEMINI_API_KEY = credentials.get('gemini_api_key')
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"WARNING: Could not load GEMINI_API_KEY from credentials.json: {e}")

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
else:
    print("WARNING: GEMINI_API_KEY not found. The recognition feature will not work.")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# Make upload path absolute
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 
    'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'
}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

COMPETITION_SPECS_FOLDER = 'competition_specs'
COMPETITION_REPORTS_FOLDER = 'competition_report_templates'
COMPETITION_TEMPLATE_DOCS_FOLDER = 'competition_template_documents'

MAIL_CONFIG_FILE_PATH = "mail_info.json"
mail_config = {}

try:
    with open(MAIL_CONFIG_FILE_PATH, 'r') as f:
        mail_config = json.load(f)
    print(f"Successfully loaded mail configuration from {MAIL_CONFIG_FILE_PATH}")
except FileNotFoundError:
    print(f"WARNING: {MAIL_CONFIG_FILE_PATH} not found. Using default/placeholder mail settings.")
except json.JSONDecodeError:
    print(f"WARNING: Error decoding {MAIL_CONFIG_FILE_PATH}. Ensure it's valid JSON. Using default/placeholder mail settings.")
except Exception as e:
    print(f"WARNING: An unexpected error occurred while loading {MAIL_CONFIG_FILE_PATH}: {e}. Using default/placeholder mail settings.")

app.config['MAIL_SERVER'] = mail_config.get('MAIL_SERVER', 'smtp.example.com')
app.config['MAIL_PORT'] = int(mail_config.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = str(mail_config.get('MAIL_USE_TLS', 'true')).lower() in ['true', '1', 't']
app.config['MAIL_USE_SSL'] = str(mail_config.get('MAIL_USE_SSL', 'false')).lower() in ['true', '1', 't']
app.config['MAIL_USERNAME'] = mail_config.get('MAIL_USERNAME', 'your-email@example.com')
app.config['MAIL_PASSWORD'] = mail_config.get('MAIL_PASSWORD', 'your-email-password')

default_sender_config = mail_config.get('MAIL_DEFAULT_SENDER', ('Proje Yönetim Sistemi Yöneticisi', 'noreply@example.com'))
if isinstance(default_sender_config, list) and len(default_sender_config) == 2:
    app.config['MAIL_DEFAULT_SENDER'] = tuple(default_sender_config)
elif isinstance(default_sender_config, str):
    app.config['MAIL_DEFAULT_SENDER'] = default_sender_config
else:
    app.config['MAIL_DEFAULT_SENDER'] = ('Proje Yönetim Sistemi Yöneticisi', 'noreply@example.com')

if app.config['MAIL_USERNAME'] == 'your-email@example.com' or app.config['MAIL_SERVER'] == 'smtp.example.com':
    print("WARNING: Mail server settings are using placeholders. Email sending may not function correctly.")

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

mail = Mail(app)

GOOGLE_CLIENT_ID = None
GOOGLE_CLIENT_SECRET = None
CREDENTIALS_FILE_PATH = "credentials.json"

try:
    with open(CREDENTIALS_FILE_PATH, 'r') as f:
        credentials = json.load(f)
        if 'web' in credentials:
            GOOGLE_CLIENT_ID = credentials['web'].get('client_id')
            GOOGLE_CLIENT_SECRET = credentials['web'].get('client_secret')
        elif 'client_id' in credentials and 'client_secret' in credentials:
            GOOGLE_CLIENT_ID = credentials.get('client_id')
            GOOGLE_CLIENT_SECRET = credentials.get('client_secret')
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        print(f"WARNING: Could not load GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET from {CREDENTIALS_FILE_PATH}. Using placeholders.")
        GOOGLE_CLIENT_ID = 'YOUR_GOOGLE_CLIENT_ID_HERE'
        GOOGLE_CLIENT_SECRET = 'YOUR_GOOGLE_CLIENT_SECRET_HERE'
except FileNotFoundError:
    print(f"WARNING: {CREDENTIALS_FILE_PATH} not found. Using placeholder Google OAuth credentials.")
    GOOGLE_CLIENT_ID = 'YOUR_GOOGLE_CLIENT_ID_HERE'
    GOOGLE_CLIENT_SECRET = 'YOUR_GOOGLE_CLIENT_SECRET_HERE'
except json.JSONDecodeError:
    print(f"WARNING: Error decoding {CREDENTIALS_FILE_PATH}. Ensure it's valid JSON. Using placeholder Google OAuth credentials.")
    GOOGLE_CLIENT_ID = 'YOUR_GOOGLE_CLIENT_ID_HERE'
    GOOGLE_CLIENT_SECRET = 'YOUR_GOOGLE_CLIENT_SECRET_HERE'
except Exception as e:
    print(f"WARNING: An unexpected error occurred while loading {CREDENTIALS_FILE_PATH}: {e}. Using placeholder Google OAuth credentials.")
    GOOGLE_CLIENT_ID = 'YOUR_GOOGLE_CLIENT_ID_HERE'
    GOOGLE_CLIENT_SECRET = 'YOUR_GOOGLE_CLIENT_SECRET_HERE'

app.config['GOOGLE_CLIENT_ID'] = GOOGLE_CLIENT_ID
app.config['GOOGLE_CLIENT_SECRET'] = GOOGLE_CLIENT_SECRET

if app.config['GOOGLE_CLIENT_ID'] == 'YOUR_GOOGLE_CLIENT_ID_HERE' or app.config['GOOGLE_CLIENT_SECRET'] == 'YOUR_GOOGLE_CLIENT_SECRET_HERE':
    print("WARNING: Google OAuth credentials are using placeholders. Google login will not function correctly.")

oauth = OAuth(app)

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = "Lütfen bu sayfaya erişmek için giriş yapın."

team_member_association = db.Table('team_member_association',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('team_id', db.Integer, db.ForeignKey('team.id'), primary_key=True)
)

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=True)
    role = db.Column(db.String(20), nullable=False, default='student')
    email_verified = db.Column(db.Boolean, default=False)
    email_verification_token = db.Column(db.String(36), nullable=True)
    oauth_provider = db.Column(db.String(50), nullable=True)
    oauth_id = db.Column(db.String(100), nullable=True)
    
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_by = db.relationship('User', remote_side=[id], backref=db.backref('created_users', lazy='dynamic'))

    created_teams = db.relationship('Team', foreign_keys='Team.advisor_id', backref='advisor', lazy=True)
    member_of_teams = db.relationship('Team', secondary=team_member_association, lazy='subquery',
                                      backref=db.backref('members', lazy=True))
    created_projects = db.relationship('Project', foreign_keys='Project.creator_id', backref='creator', lazy=True)

    @property
    def is_student(self):
        return self.role == "student"

    @property
    def is_teacher(self):
        return self.role == "teacher"

    @property
    def is_admin(self):
        return self.role == "admin"

    @property
    def is_kurum_yoneticisi(self):
        return self.role == "kurum_yoneticisi"

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"

class StudentInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    student_number = db.Column(db.String(50), nullable=False)
    tc_kimlik_no = db.Column(db.String(11), nullable=False)
    student_class = db.Column(db.String(20), nullable=False)
    user = db.relationship('User', backref=db.backref('student_info', uselist=False, cascade="all, delete-orphan"))

    def __repr__(self):
        return f"<StudentInfo for User {self.user_id}>"

class TeacherInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    tc_kimlik_no = db.Column(db.String(11), nullable=False)
    user = db.relationship('User', backref=db.backref('teacher_info', uselist=False, cascade="all, delete-orphan"))

    def __repr__(self):
        return f"<TeacherInfo for User {self.user_id}>"

class Team(db.Model):
    __tablename__ = 'team'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    advisor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    projects = db.relationship('Project', backref='team', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Team {self.name}>"

class Project(db.Model):
    __tablename__ = 'project'
    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.String(100), nullable=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    progress = db.Column(db.Integer, default=0)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    competition_template_id = db.Column(db.Integer, db.ForeignKey('competition_template.id'), nullable=True)

    main_topic = db.Column(db.String(250), nullable=True)
    common_sub_theme = db.Column(db.String(250), nullable=True)

    # New field for MEB approval status
    meg_approval_status = db.Column(db.String(50), nullable=False, default='İzin İstenmedi') # Options: 'İzin Alındı', 'İzin Beklemede', 'İzin İstenmedi'

    # New field for project completion status
    is_completed = db.Column(db.Boolean, nullable=False, default=False)

    # New field for project status tracking notes
    status_notes = db.Column(db.Text, nullable=True)

    # New field for unique survey token
    survey_token = db.Column(db.String(36), unique=True, nullable=True)

    timeline_events = db.relationship('TimelineEvent', backref='project', lazy=True, cascade="all, delete-orphan")
    tasks = db.relationship('Task', backref='project', lazy=True, cascade="all, delete-orphan")
    files = db.relationship('ProjectFile', backref='project', lazy=True, cascade="all, delete-orphan")
    images = db.relationship('ProjectImage', backref='project', lazy=True, cascade="all, delete-orphan")
    survey_responses = db.relationship('SurveyResponse', backref='project', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Project {self.name}>"

class TimelineEvent(db.Model):
    __tablename__ = 'timeline_event'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    description = db.Column(db.Text, nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    is_from_template = db.Column(db.Boolean, default=False, nullable=False)
    competition_template_date_id = db.Column(db.Integer, db.ForeignKey('competition_template_date.id'), nullable=True)

    def __repr__(self):
        return f"<TimelineEvent {self.description[:30]} for Project {self.project_id}>"

class Task(db.Model):
    __tablename__ = 'task'
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    due_date = db.Column(db.Date, nullable=True)
    is_complete = db.Column(db.Boolean, default=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)

    def __repr__(self):
        return f"<Task {self.description[:30]} for Project {self.project_id}>"

class ProjectFile(db.Model):
    __tablename__ = 'project_file'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    path = db.Column(db.String(512), nullable=False, unique=True)
    uploaded_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)

    def __repr__(self):
        return f"<ProjectFile {self.name} for Project {self.project_id}>"

class ProjectImage(db.Model):
    __tablename__ = 'project_image'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    path = db.Column(db.String(512), nullable=False, unique=True)
    uploaded_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)

    def __repr__(self):
        return f"<ProjectImage {self.name} for Project {self.project_id}>"

class CompetitionTemplate(db.Model):
    __tablename__ = 'competition_template'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    topics_themes_json = db.Column(db.Text, nullable=True)
    requires_meg_approval = db.Column(db.Boolean, default=False)
    
    ky_creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ky_creator = db.relationship('User', foreign_keys=[ky_creator_id])
    
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    projects = db.relationship('Project', backref='competition_template', lazy='dynamic')

    def __repr__(self):
        return f"<CompetitionTemplate {self.name}>"

class CompetitionTemplateDate(db.Model):
    __tablename__ = 'competition_template_date'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    date = db.Column(db.Date, nullable=False)
    competition_template_id = db.Column(db.Integer, db.ForeignKey('competition_template.id'), nullable=False)
    template = db.relationship('CompetitionTemplate', backref=db.backref('defined_dates', lazy='dynamic', cascade="all, delete-orphan"))

    def __repr__(self):
        return f"<CompetitionTemplateDate {self.name} ({self.date}) for Template {self.competition_template_id}>"

class CompetitionTemplateDocument(db.Model):
    __tablename__ = 'competition_template_document'
    id = db.Column(db.Integer, primary_key=True)
    display_name = db.Column(db.String(150), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    competition_template_id = db.Column(db.Integer, db.ForeignKey('competition_template.id'), nullable=False)
    template = db.relationship('CompetitionTemplate', backref=db.backref('defined_documents', lazy='dynamic', cascade="all, delete-orphan"))

    def __repr__(self):
        return f"<CompetitionTemplateDocument {self.display_name} for Template {self.competition_template_id}>"

class SurveyResponse(db.Model):
    __tablename__ = 'survey_response'
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    respondent_name = db.Column(db.String(150), nullable=False)
    work_results_feedback = db.Column(db.Text, nullable=False)
    contribution_feedback = db.Column(db.Text, nullable=False)
    suggestions_feedback = db.Column(db.Text, nullable=True)
    submitted_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<SurveyResponse for Project {self.project_id}>"

class Material(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=True)
    quantity_in_stock = db.Column(db.Integer, nullable=False, default=0)
    is_scrap = db.Column(db.Boolean, default=False, nullable=False)
    quantity_scrapped = db.Column(db.Integer, nullable=False, default=0)
    # Relation to request items
    requests = db.relationship('MaterialRequestItem', back_populates='material')

    def __repr__(self):
        return f'<Material {self.name}>'

class MaterialRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    request_date = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    status = db.Column(db.String(50), nullable=False, default='Danışman Onayı Bekliyor')
    approval_token = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    advisor_notes = db.Column(db.Text, nullable=True) # For rejection reasons etc.
    return_processed = db.Column(db.Boolean, default=False, nullable=False)

    project = db.relationship('Project', backref='material_requests')
    requester = db.relationship('User', backref='material_requests')
    items = db.relationship('MaterialRequestItem', backref='request', lazy='dynamic', cascade="all, delete-orphan")

    def __repr__(self):
        return f"<MaterialRequest {self.id} for Project {self.project_id}>"

class MaterialRequestItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('material_request.id'), nullable=False)
    material_id = db.Column(db.Integer, db.ForeignKey('material.id'), nullable=False)
    quantity_requested = db.Column(db.Integer, nullable=False, default=1)
    quantity_returned_working = db.Column(db.Integer, nullable=False, default=0)
    quantity_returned_broken = db.Column(db.Integer, nullable=False, default=0)

    material = db.relationship('Material', back_populates='requests')

    def __repr__(self):
        return f"{self.quantity_requested}x {self.material.name} for Request {self.request_id}"

class ExternalMaterialRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    request_date = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    status = db.Column(db.String(50), nullable=False, default='Beklemede') # Options: Beklemede, Onaylandı, Reddedildi
    ky_notes = db.Column(db.Text, nullable=True) # For KY notes/rejection reasons

    project = db.relationship('Project', backref='external_material_requests')
    requester = db.relationship('User', backref='external_material_requests')
    items = db.relationship('ExternalMaterialRequestItem', backref='request', lazy='dynamic', cascade="all, delete-orphan")

    def __repr__(self):
        return f"<ExternalMaterialRequest {self.id} for Project {self.project_id}>"

class ExternalMaterialRequestItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('external_material_request.id'), nullable=False)
    product_name = db.Column(db.String(150), nullable=False)
    product_link = db.Column(db.String(512), nullable=True)
    category = db.Column(db.String(50), nullable=False)
    estimated_price = db.Column(db.Float, nullable=True)
    quantity = db.Column(db.Integer, nullable=False, default=1)

    def __repr__(self):
        return f"{self.quantity}x {self.product_name} for External Request {self.request_id}"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def kurum_yoneticisi_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'kurum_yoneticisi':
            flash('Bu sayfayı görüntüleme yetkiniz yok.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def get_project_specific_upload_dir(project_id, type_folder):
    return os.path.join(app.config['UPLOAD_FOLDER'], type_folder, str(project_id))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.route('/')
def main_page():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('welcome.html')

@app.route('/dashboard') 
@login_required
def dashboard():
    # Get teams where the user is an advisor
    advisor_teams = Team.query.filter_by(advisor_id=current_user.id).all()
    
    # Get teams where the user is a member
    member_teams = current_user.member_of_teams
    
    # Combine and remove duplicates
    all_teams = list(set(advisor_teams + member_teams))
    
    all_projects = []
    for team in all_teams:
        all_projects.extend(team.projects)
        
    return render_template('index.html', user=current_user, user_teams=all_teams, projects=all_projects)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        # Basic Validation
        if not all([username, email, password, role]):
            flash('Lütfen tüm alanları doldurun.', 'danger')
            return render_template('signup.html')

        if User.query.filter_by(username=username).first():
            flash('Bu kullanıcı adı zaten alınmış.', 'danger')
            return render_template('signup.html')
        
        if User.query.filter_by(email=email).first():
            flash('Bu e-posta adresi zaten kullanılıyor.', 'danger')
            return render_template('signup.html')

        try:
            validate_email(email)
        except EmailNotValidError as e:
            flash(str(e), 'danger')
            return render_template('signup.html')

        # Store basic info in session and redirect
        session['signup_form'] = {
            'username': username,
            'email': email,
            'password': password,
            'role': role
        }

        if role == 'student':
            return redirect(url_for('signup_student_info'))
        elif role == 'teacher':
            return redirect(url_for('signup_teacher_info'))
        else:
            # For other roles like admin, etc., if they can be created via signup,
            # handle them here. For now, we assume only student/teacher signup.
            flash('Geçersiz rol seçimi.', 'danger')
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/signup/student-info', methods=['GET', 'POST'])
def signup_student_info():
    if 'signup_form' not in session:
        flash('Kayıt işlemi başlatılamadı. Lütfen tekrar deneyin.', 'warning')
        return redirect(url_for('signup'))
        
    if request.method == 'POST':
        signup_data = session['signup_form']
        
        student_number = request.form.get('student_number')
        tc_kimlik_no = request.form.get('tc_kimlik_no')
        student_class = request.form.get('student_class')

        if not all([student_number, tc_kimlik_no, student_class]):
            flash('Lütfen tüm alanları doldurun.', 'danger')
            return render_template('signup_student_info.html')

        hashed_password = bcrypt.generate_password_hash(signup_data['password']).decode('utf-8')
        verification_token = str(uuid.uuid4())

        new_user = User(
            username=signup_data['username'],
            email=signup_data['email'],
            password_hash=hashed_password,
            role=signup_data['role'],
            email_verification_token=verification_token
        )
        db.session.add(new_user)
        db.session.flush() # Flush to get the new_user.id

        student_info = StudentInfo(
            user_id=new_user.id,
            student_number=student_number,
            tc_kimlik_no=tc_kimlik_no,
            student_class=student_class
        )
        db.session.add(student_info)
        db.session.commit()

        try:
            send_verification_email(new_user)
            flash("Hesabınız başarıyla oluşturuldu! Hesabınızı etkinleştirmek için lütfen e-postanızı kontrol edin.", 'success')
        except Exception as e:
            app.logger.error(f"Email sending failed for {new_user.email}: {e}")
            flash("Hesabınız oluşturuldu ancak doğrulama e-postası gönderilemedi. Lütfen yöneticinizle iletişime geçin.", 'warning')

        # Clear session data
        session.pop('signup_form', None)

        return redirect(url_for('login'))

    return render_template('signup_student_info.html')

@app.route('/signup/teacher-info', methods=['GET', 'POST'])
def signup_teacher_info():
    if 'signup_form' not in session:
        flash('Kayıt işlemi başlatılamadı. Lütfen tekrar deneyin.', 'warning')
        return redirect(url_for('signup'))

    if request.method == 'POST':
        signup_data = session['signup_form']
        
        tc_kimlik_no = request.form.get('tc_kimlik_no')

        if not tc_kimlik_no:
            flash('Lütfen T.C. Kimlik No alanını doldurun.', 'danger')
            return render_template('signup_teacher_info.html')
            
        hashed_password = bcrypt.generate_password_hash(signup_data['password']).decode('utf-8')
        verification_token = str(uuid.uuid4())
        
        new_user = User(
            username=signup_data['username'],
            email=signup_data['email'],
            password_hash=hashed_password, 
            role=signup_data['role'],
            email_verification_token=verification_token
        )
        db.session.add(new_user)
        db.session.flush() # Flush to get the new_user.id

        teacher_info = TeacherInfo(
            user_id=new_user.id,
            tc_kimlik_no=tc_kimlik_no
        )
        db.session.add(teacher_info)
        db.session.commit()

        try:
            send_verification_email(new_user)
            flash("Hesabınız başarıyla oluşturuldu! Hesabınızı etkinleştirmek için lütfen e-postanızı kontrol edin.", 'success')
        except Exception as e:
            app.logger.error(f"Email sending failed for {new_user.email}: {e}")
            flash("Hesabınız oluşturuldu ancak doğrulama e-postası gönderilemedi. Lütfen yöneticinizle iletişime geçin.", 'warning')

        # Clear session data
        session.pop('signup_form', None)
            
        return redirect(url_for('login'))

    return render_template('signup_teacher_info.html')

@app.route('/verify_email/<token>', methods=['GET'])
def verify_email(token):
    user = User.query.filter_by(email_verification_token=token).first()
    if user:
        user.email_verified = True
        user.email_verification_token = None
        db.session.commit()
        flash("E-posta başarıyla doğrulandı! Artık giriş yapabilirsiniz.", 'success')
    else:
        flash("Geçersiz veya süresi dolmuş doğrulama anahtarı.", 'danger')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        login_identifier = request.form.get('login_identifier')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False

        print(f"[DEBUG] Login attempt for identifier: {login_identifier}")

        user_obj = User.query.filter((User.username == login_identifier) | (User.email == login_identifier)).first()

        if user_obj:
            print(f"[DEBUG] User found: {user_obj.username}, OAuth: {user_obj.oauth_provider is not None}")
            print(f"[DEBUG] Password hash exists: {user_obj.password_hash is not None}")
            print(f"[DEBUG] Email verified: {user_obj.email_verified}")
            if user_obj.password_hash:
                password_match = bcrypt.check_password_hash(user_obj.password_hash, password)
                print(f"[DEBUG] Password match: {password_match}")
            else:
                password_match = False
                print("[DEBUG] No password hash for user (likely OAuth user).")
        else:
            print("[DEBUG] User not found.")
            password_match = False

        if user_obj and user_obj.password_hash and password_match:
            if not user_obj.email_verified:
                flash("E-postanız doğrulanmamış. Lütfen doğrulama bağlantısı için e-postanızı kontrol edin.", 'warning')
                print("[DEBUG] Login failed: Email not verified.")
                return redirect(url_for('login'))
            
            login_user(user_obj, remember=remember)
            flash("Giriş başarılı!", 'success')
            print(f"[DEBUG] Login successful for user: {user_obj.username}")
            
            if user_obj.is_admin:
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash("Geçersiz kullanıcı adı veya şifre.", 'danger')
            print("[DEBUG] Login failed: Invalid credentials or OAuth user trying password login.")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Çıkış yaptınız.", 'info')
    return redirect(url_for('main_page'))

@app.route('/project/<int:project_id>')
@login_required
def project_detail(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Check if user has access to this project
    user_is_member = current_user in project.team.members
    user_is_advisor = current_user.id == project.team.advisor_id
    user_is_ky_or_admin = current_user.role in ['kurum_yoneticisi', 'admin']

    if not (user_is_member or user_is_advisor or user_is_ky_or_admin):
        flash('Bu projeyi görüntüleme yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))

    can_edit_project = user_is_member or user_is_advisor
    
    # Fetch files and images
    project_files = ProjectFile.query.filter_by(project_id=project.id).order_by(ProjectFile.uploaded_at.desc()).all()
    project_images = ProjectImage.query.filter_by(project_id=project.id).order_by(ProjectImage.uploaded_at.desc()).all()

    # Fetch timeline events and tasks
    timeline_events = TimelineEvent.query.filter_by(project_id=project.id).order_by(TimelineEvent.date).all()
    tasks = Task.query.filter_by(project_id=project.id).order_by(Task.due_date.asc().nullslast()).all()
    
    # Check for overdue events and tasks
    today = datetime.now(timezone.utc).date()
    for event in timeline_events:
        event.is_overdue = event.date < today
    for task in tasks:
        task.is_overdue = (task.due_date and task.due_date < today and not task.is_complete)

    # Fetch material requests
    material_requests = MaterialRequest.query.filter_by(project_id=project.id).order_by(MaterialRequest.request_date.desc()).all()


    return render_template(
        'project_detail.html', 
        project=project, 
        project_files=project_files, 
        project_images=project_images,
        timeline_events=timeline_events,
        tasks=tasks,
        can_edit_project=can_edit_project, 
        material_requests=material_requests
    )

@app.route('/project/<int:project_id>/update_progress', methods=['POST'])
@login_required
def update_progress(project_id):
    project = Project.query.get_or_404(project_id)
    team = project.team

    if not (current_user in team.members or current_user.id == team.advisor_id):
        flash('Bu projenin ilerlemesini güncelleme yetkiniz yok.', 'danger')
        return redirect(url_for('project_detail', project_id=project_id))

    try:
        progress = int(request.form['progress'])
        if 0 <= progress <= 100:
            project.progress = progress
            db.session.commit()
            flash('Proje ilerlemesi başarıyla güncellendi.', 'success')
        else:
            flash('Geçersiz ilerleme değeri. 0 ile 100 arasında olmalıdır.', 'warning')
    except ValueError:
        flash('Geçersiz ilerleme değeri. Bir sayı olmalıdır.', 'warning')
    except Exception as e:
        db.session.rollback()
        flash(f'İlerlemeyi güncellerken bir hata oluştu: {str(e)}', 'danger')
        print(f"Error updating progress for project {project.id} by {current_user.username}: {e}")
        
    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/project/<int:project_id>/upload_file', methods=['POST'])
@login_required
def upload_project_file(project_id):
    project = Project.query.get_or_404(project_id)
    team = project.team

    if not (current_user in team.members or current_user.id == team.advisor_id):
        flash('Bu projeye dosya yükleme yetkiniz yok.', 'danger')
        return redirect(url_for('project_detail', project_id=project_id))

    if 'project_file' not in request.files:
        flash('İstekte dosya bölümü yok.', 'warning')
        return redirect(url_for('project_detail', project_id=project_id))
    
    file = request.files['project_file']

    if file.filename == '':
        flash('Yüklemek için dosya seçilmedi.', 'warning')
        return redirect(url_for('project_detail', project_id=project_id))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        project_files_dir = get_project_specific_upload_dir(project_id, 'files')
        if not os.path.exists(project_files_dir):
            os.makedirs(project_files_dir)
        
        base, ext = os.path.splitext(filename)
        counter = 1
        temp_filename = filename
        while os.path.exists(os.path.join(project_files_dir, temp_filename)):
            temp_filename = f"{base}_{counter}{ext}"
            counter += 1
        filename = temp_filename
        
        file_path_on_disk = os.path.join(project_files_dir, filename)
        
        try:
            file.save(file_path_on_disk)
            relative_path = os.path.join('files', str(project_id), filename).replace('\\', '/')
            
            new_db_file = ProjectFile(
                name=filename,
                path=relative_path,
                project_id=project.id
            )
            db.session.add(new_db_file)
            db.session.commit()
            flash(f'"{filename}" dosyası başarıyla yüklendi!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Dosya yükleme ve veritabanı güncelleme sırasında bir hata oluştu: {str(e)}', 'danger')
            print(f"Error uploading file for project {project.id}: {e}")
            if os.path.exists(file_path_on_disk):
                try:
                    os.remove(file_path_on_disk)
                except OSError as ose:
                    print(f"Error removing file {file_path_on_disk} after DB error: {ose}")
    else:
        flash('Dosya türüne izin verilmiyor.', 'danger')
    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/project/<int:project_id>/upload_image', methods=['POST'])
@login_required
def upload_project_image(project_id):
    project = Project.query.get_or_404(project_id)
    team = project.team

    if not (current_user in team.members or current_user.id == team.advisor_id):
        flash('Bu projeye resim yükleme yetkiniz yok.', 'danger')
        return redirect(url_for('project_detail', project_id=project_id))

    if 'project_image' not in request.files:
        flash('İstekte resim bölümü yok.', 'warning')
        return redirect(url_for('project_detail', project_id=project_id))

    image = request.files['project_image']

    if image.filename == '':
        flash('Yüklemek için resim seçilmedi.', 'warning')
        return redirect(url_for('project_detail', project_id=project_id))

    if image and allowed_file(image.filename):
        filename = secure_filename(image.filename)
        project_images_dir = get_project_specific_upload_dir(project_id, 'images')
        if not os.path.exists(project_images_dir):
            os.makedirs(project_images_dir)

        base, ext = os.path.splitext(filename)
        counter = 1
        temp_filename = filename
        while os.path.exists(os.path.join(project_images_dir, temp_filename)):
            temp_filename = f"{base}_{counter}{ext}"
            counter += 1
        filename = temp_filename

        image_path_on_disk = os.path.join(project_images_dir, filename)

        try:
            image.save(image_path_on_disk)
            relative_path = os.path.join('images', str(project_id), filename).replace('\\', '/')

            new_db_image = ProjectImage(
                name=filename,
                path=relative_path,
                project_id=project.id
            )
            db.session.add(new_db_image)
            db.session.commit()
            flash(f'"{filename}" resmi başarıyla yüklendi!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Resim yükleme ve veritabanı güncelleme sırasında bir hata oluştu: {str(e)}', 'danger')
            print(f"Error uploading image for project {project.id}: {e}")
            if os.path.exists(image_path_on_disk):
                try:
                    os.remove(image_path_on_disk)
                except OSError as ose:
                    print(f"Error removing image {image_path_on_disk} after DB error: {ose}")
    else:
        flash('Resim türüne izin verilmiyor.', 'danger')
    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/uploads/<path:folder>/<path:project_id_str>/<path:filename>')
@login_required
def uploaded_file_or_image(folder, project_id_str, filename):
    try:
        project_id_int = int(project_id_str)
    except ValueError:
        flash("URL'de geçersiz proje tanımlayıcısı.", "danger")
        return redirect(url_for('dashboard'))

    project = Project.query.get(project_id_int)

    if not project:
        flash("İstenen dosya için proje bulunamadı.", "danger")
        return redirect(url_for('dashboard'))

    team = project.team
    if not (current_user in team.members or current_user.id == team.advisor_id):
        flash('Bu projenin dosyalarına erişim yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))
        
    directory = os.path.join(app.config['UPLOAD_FOLDER'], folder, project_id_str)
    
    abs_directory = os.path.abspath(directory)
    abs_upload_folder = os.path.abspath(app.config['UPLOAD_FOLDER'])

    if not abs_directory.startswith(abs_upload_folder):
        flash("Kısıtlanmış dosya yoluna erişim denemesi.", "danger")
        return redirect(url_for('dashboard'))

    if folder == 'files':
        db_file = ProjectFile.query.filter_by(project_id=project.id, name=filename).first()
    elif folder == 'images':
        db_file = ProjectImage.query.filter_by(project_id=project.id, name=filename).first()
    else:
        db_file = None

    if not db_file:
        flash("Proje kayıtlarında dosya veya resim bulunamadı.", "danger")
        return redirect(url_for('project_detail', project_id=project.id))

    return send_from_directory(directory, filename)

@app.route('/project/<int:project_id>/add_timeline_event', methods=['POST'])
@login_required
def add_timeline_event(project_id):
    project = Project.query.get_or_404(project_id)

    if not current_user.is_kurum_yoneticisi:
        flash('Sadece Kurum Yöneticileri zaman çizelgesine özel etkinlik ekleyebilir.', 'danger')
        return redirect(url_for('project_detail', project_id=project_id))

    event_date_str = request.form.get('event_date')
    event_description = request.form.get('event_description')

    if not event_date_str or not event_description:
        flash('Zaman çizelgesi için etkinlik tarihi ve açıklaması gereklidir.', 'danger')
        return redirect(url_for('project_detail', project_id=project_id))

    try:
        event_date_obj = datetime.strptime(event_date_str, '%Y-%m-%d').date()
    except ValueError:
        flash('Zaman çizelgesi etkinliği için geçersiz tarih formatı. Lütfen YYYY-AA-GG formatını kullanın.', 'warning')
        return redirect(url_for('project_detail', project_id=project_id))

    new_event = TimelineEvent(
        date=event_date_obj,
        description=event_description,
        project_id=project.id
    )
    try:
        db.session.add(new_event)
        db.session.commit()
        flash('Zaman çizelgesi etkinliği eklendi.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Zaman çizelgesi etkinliği eklenirken bir hata oluştu: {str(e)}', 'danger')
        print(f"Error adding timeline event to project {project.id} by {current_user.username}: {e}")
    
    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/project/<int:project_id>/add_task', methods=['POST'])
@login_required
def add_task(project_id):
    project = Project.query.get_or_404(project_id)
    team = project.team

    if not (current_user in team.members or current_user.id == team.advisor_id):
        flash('Bu projeye görev ekleme yetkiniz yok.', 'danger')
        return redirect(url_for('project_detail', project_id=project_id))

    task_description = request.form.get('task_description')
    task_due_date_str = request.form.get('task_due_date')

    if not task_description:
        flash('Görev açıklaması gereklidir.', 'danger')
        return redirect(url_for('project_detail', project_id=project_id))
    
    task_due_date_obj = None
    if task_due_date_str:
        try:
            task_due_date_obj = datetime.strptime(task_due_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Görev için geçersiz bitiş tarihi formatı. Lütfen YYYY-AA-GG formatını kullanın veya boş bırakın.', 'warning')
            return redirect(url_for('project_detail', project_id=project_id))

    new_task = Task(
        description=task_description,
        due_date=task_due_date_obj,
        is_complete=False,
        project_id=project.id
    )
    try:
        db.session.add(new_task)
        db.session.commit()
        flash('Görev başarıyla eklendi.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Görev eklenirken bir hata oluştu: {str(e)}', 'danger')
        print(f"Error adding task to project {project.id} by {current_user.username}: {e}")

    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/project/<int:project_id>/task/<int:task_id>/toggle_complete', methods=['POST'])
@login_required
def toggle_task_completion(project_id, task_id):
    project = Project.query.get_or_404(project_id)
    team = project.team

    if not (current_user in team.members or current_user.id == team.advisor_id):
        flash('Bu görevin durumunu değiştirme yetkiniz yok.', 'danger')
        return redirect(url_for('project_detail', project_id=project_id))

    task_to_toggle = Task.query.filter_by(id=task_id, project_id=project.id).first_or_404()
    
    task_to_toggle.is_complete = not task_to_toggle.is_complete
    try:
        db.session.commit()
        status_tr = "tamamlandı" if task_to_toggle.is_complete else "beklemede"
        flash(f'"{task_to_toggle.description[:30]}..." görevi {status_tr} olarak işaretlendi.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Görev güncellenirken bir hata oluştu: {str(e)}', 'danger')
        print(f"Error toggling task {task_id} for project {project.id} by {current_user.username}: {e}")

    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/project/<int:project_id>/update_meg_status', methods=['POST'])
@login_required
def update_meg_status(project_id):
    project = Project.query.get_or_404(project_id)
    # Authorization: only the advisor or a KY of the advisor can change status
    is_advisor = current_user.id == project.team.advisor_id
    is_ky = current_user.is_kurum_yoneticisi and project.team.advisor.creator_id == current_user.id
    
    if not (is_advisor or is_ky):
        flash('Bu işlemi yapma yetkiniz yok.', 'danger')
        return redirect(url_for('project_detail', project_id=project.id))

    new_status = request.form.get('meg_status')
    if new_status in ['İzin Alındı', 'İzin Beklemede', 'İzin İstenmedi']:
        project.meg_approval_status = new_status
        db.session.commit()
        flash('MEB izin durumu güncellendi.', 'success')
    return redirect(url_for('project_detail', project_id=project.id))

@app.route('/project/<int:project_id>/update_application_id', methods=['POST'])
@login_required
def update_application_id(project_id):
    project = Project.query.get_or_404(project_id)
    if current_user != project.team.advisor:
        flash('Bu işlemi yapma yetkiniz yok.', 'danger')
        return redirect(url_for('project_detail', project_id=project_id))
    
    new_app_id = request.form.get('application_id').strip()
    
    project.application_id = new_app_id if new_app_id else None
    db.session.commit()
    flash('Proje Başvuru ID başarıyla güncellendi.', 'success')
    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/project/<int:project_id>/toggle_completion', methods=['POST'])
@login_required
def toggle_project_completion(project_id):
    project = Project.query.get_or_404(project_id)
    if current_user.id != project.team.advisor_id:
        flash('Bu işlemi yapma yetkiniz yok.', 'danger')
        return redirect(url_for('project_detail', project_id=project_id))

    was_completed = project.is_completed
    project.is_completed = not project.is_completed
    
    redirect_url = url_for('project_detail', project_id=project.id)

    # If the project is being marked as complete for the first time
    if project.is_completed and not was_completed:
        if not project.survey_token:
            project.survey_token = str(uuid.uuid4())
        
        db.session.commit()

        survey_url = url_for('survey_page', token=project.survey_token, _external=True)
        
        # Send mail to advisor
        send_survey_email(project.team.advisor.email, project.team.advisor.username, project.name, survey_url)
        # Send mail to all members
        for member in project.team.members:
            if member.id != project.team.advisor.id:
                send_survey_email(member.email, member.username, project.name, survey_url)

        flash(f'"{project.name}" projesi başarıyla tamamlandı olarak işaretlendi. Geri bildirim anketini doldurmayı unutmayın!', 'success')
        redirect_url = url_for('project_detail', project_id=project.id, show_survey_popup='true')
    else:
        db.session.commit()
        status_message = "tamamlandı" if project.is_completed else "devam ediyor olarak işaretlendi"
        flash(f'"{project.name}" projesi başarıyla {status_message}.', 'success')
    
    return redirect(redirect_url)

@app.route('/project/<int:project_id>/update_status_notes', methods=['POST'])
@login_required
def update_status_notes(project_id):
    project = Project.query.get_or_404(project_id)
    team = project.team

    if not (current_user in team.members or current_user.id == team.advisor_id):
        flash('Bu proje üzerinde işlem yapma yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))

    notes = request.form.get('status_notes')
    project.status_notes = notes
    db.session.commit()
    flash('Proje durum notları başarıyla güncellendi.', 'success')
    return redirect(url_for('project_detail', project_id=project.id))

oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

@app.route('/login/google')
def auth_google_login():
    redirect_uri = url_for('auth_google_authorize', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/authorize/google')
def auth_google_authorize():
    try:
        token = oauth.google.authorize_access_token()
        user_info_google = oauth.google.parse_id_token(token, nonce=session.get('nonce'))
    except Exception as e:
        flash(f'Google OAuth Hatası: {str(e)}', 'danger')
        return redirect(url_for('login'))
    
    user = get_or_create_oauth_user('google', user_info_google)
    if user:
        flash(f'{user.username} olarak Google ile başarıyla giriş yapıldı!', 'success')
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

def get_or_create_oauth_user(provider_name, oauth_user_info):
    oauth_email = oauth_user_info.get('email')
    oauth_subject_id = str(oauth_user_info.get('sub')) 

    if not oauth_email:
        flash(f'{provider_name.capitalize()} tarafından e-posta sağlanmadı. Giriş yapılamaz veya kaydolunamaz.', 'danger')
        return None

    user = User.query.filter_by(oauth_provider=provider_name, oauth_id=oauth_subject_id).first()
    if user:
        user.email_verified = True
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Error updating email_verified for OAuth user {user.email}: {e}")
        login_user(user)
        return user

    user_by_email = User.query.filter_by(email=oauth_email).first()
    if user_by_email:
        if not user_by_email.oauth_provider:
            user_by_email.oauth_provider = provider_name
            user_by_email.oauth_id = oauth_subject_id
            user_by_email.email_verified = True
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                flash(f'{provider_name.capitalize()} hesabı bağlanamadı. Lütfen tekrar deneyin.', 'danger')
                print(f"Error linking OAuth for user {user_by_email.email}: {e}")
                return None
            login_user(user_by_email)
            return user_by_email
        elif user_by_email.oauth_provider == provider_name and user_by_email.oauth_id == oauth_subject_id:
            user_by_email.email_verified = True
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
            login_user(user_by_email)
            return user_by_email
        else:
            flash(f'Bu e-posta zaten farklı bir giriş yöntemiyle kullanılıyor. Lütfen {oauth_email} için orijinal yönteminizle giriş yapın.', 'warning')
            return None
    else:
        username_base = oauth_user_info.get('name', oauth_email.split('@')[0])
        username = username_base
        counter = 1
        while User.query.filter_by(username=username).first():
            username = f"{username_base}{counter}"
            counter += 1

        new_user = User(
            username=username, 
            email=oauth_email, 
            role='student',
            email_verified=True,
            oauth_provider=provider_name,
            oauth_id=oauth_subject_id
        )
        try:
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return new_user
        except Exception as e:
            db.session.rollback()
            flash(f'{provider_name.capitalize()} aracılığıyla hesabınız oluşturulurken bir hata oluştu: {str(e)} Lütfen tekrar deneyin.', 'danger')
            print(f"Error creating OAuth user {username}: {e}")
            return None

def send_verification_email(user):
    token = user.email_verification_token
    verification_url = url_for('verify_email', token=token, _external=True)
    
    subject = "E-postanızı Doğrulayın - Proje Yönetim Sistemi"
    html_body = render_template('email/verify_email.html', 
                                username=user.username, 
                                verification_url=verification_url)
    text_body = f"Merhaba {user.username},\n\nLütfen aşağıdaki bağlantıya tıklayarak e-postanızı doğrulayın:\n{verification_url}\n\nEğer Proje Yönetim Sistemi'ne kayıt olmadıysanız, lütfen bu e-postayı dikkate almayın."

    msg = Message(subject, recipients=[user.email], body=text_body, html=html_body)
    
    try:
        mail.send(msg)
        print(f"Verification email supposedly sent to {user.email}")
        return True
    except Exception as e:
        print(f"Error sending verification email to {user.email}: {e}")
        flash("Doğrulama e-postanızı gönderirken bir sorunla karşılaştık. Bu devam ederse lütfen destek ile iletişime geçin.", "danger")
        return False

def create_tables():
    with app.app_context():
        db.create_all()
        print("Veritabanı tabloları oluşturuldu (eğer yoksa).")

@app.route('/create_team', methods=['GET', 'POST'])
@login_required
def create_team():
    if not (current_user.is_teacher or current_user.is_kurum_yoneticisi or current_user.is_admin):
        flash('Sadece öğretmenler, kurum yöneticileri veya adminler takım oluşturabilir.', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        team_name = request.form.get('team_name')
        if not team_name:
            flash('Takım adı gereklidir.', 'warning')
            return render_template('create_team.html') 

        existing_team = Team.query.filter_by(name=team_name, advisor_id=current_user.id).first()
        if existing_team:
            flash(f'"{team_name}" adında bir takımınız zaten mevcut. Lütfen farklı bir ad seçin.', 'warning')
            return render_template('create_team.html', team_name=team_name)

        new_team = Team(name=team_name, advisor_id=current_user.id)
        try:
            # Add the advisor as a member of their own team upon creation
            new_team.members.append(current_user)
            db.session.add(new_team)
            db.session.commit()
            flash(f'"{team_name}" takımı başarıyla oluşturuldu!', 'success')
            return redirect(url_for('dashboard')) 
        except Exception as e:
            db.session.rollback()
            flash(f'Takım oluşturulurken bir hata oluştu: {str(e)}', 'danger')
            print(f"Error creating team {team_name} by user {current_user.username}: {e}")
            return render_template('create_team.html', team_name=team_name)
            
    return render_template('create_team.html')

@app.route('/team/<int:team_id>/add_member', methods=['GET', 'POST'])
@login_required
def add_member_to_team_route(team_id):
    team = Team.query.get_or_404(team_id)

    if not (current_user.is_teacher or current_user.is_kurum_yoneticisi or current_user.is_admin) or team.advisor_id != current_user.id:
        flash('Bu takıma üye ekleme yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email_to_add = request.form.get('email')
        if not email_to_add:
            flash('E-posta adresi gereklidir.', 'warning')
            return render_template('add_member.html', team=team)

        user_to_add = User.query.filter_by(email=email_to_add).first()

        if not user_to_add:
            flash(f'"{email_to_add}" e-postası ile kullanıcı bulunamadı.', 'danger')
            return render_template('add_member.html', team=team, email=email_to_add)
        
        if user_to_add.role == 'teacher':
            flash(f'Öğretmenler takım üyesi olarak eklenemez. "{email_to_add}" bir öğretmendir.', 'warning')
            return render_template('add_member.html', team=team, email=email_to_add)
        if user_to_add.role == 'kurum_yoneticisi':
            flash(f'Kurum Yöneticileri takım üyesi olarak eklenemez. "{email_to_add}" bir Kurum Yöneticisidir.', 'warning')
            return render_template('add_member.html', team=team, email=email_to_add)
        if user_to_add.role == 'admin':
            flash(f'Adminler takım üyesi olarak eklenemez. "{email_to_add}" bir Admindir.', 'warning')
            return render_template('add_member.html', team=team, email=email_to_add)

        if user_to_add.id == team.advisor_id:
            flash(f'"{user_to_add.username}" kullanıcısı zaten bu takımın danışmanı.', 'info')
            return render_template('add_member.html', team=team, email=email_to_add)
        
        if user_to_add in team.members:
            flash(f'"{user_to_add.username}" kullanıcısı zaten bu takımın bir üyesi.', 'info')
            return render_template('add_member.html', team=team, email=email_to_add)

        try:
            team.members.append(user_to_add)
            db.session.commit()
            flash(f'"{user_to_add.username}" ({email_to_add}) kullanıcısı "{team.name}" takımına başarıyla eklendi!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Üye eklenirken bir hata oluştu: {str(e)}', 'danger')
            print(f"Error adding member {email_to_add} to team {team.id} by {current_user.username}: {e}")
            return render_template('add_member.html', team=team, email=email_to_add)

    return render_template('add_member.html', team=team)

@app.route('/team/<int:team_id>/add_project', methods=['GET', 'POST'])
@login_required
def add_project_to_team_route(team_id):
    team = Team.query.get_or_404(team_id)
    if current_user != team.advisor:
        flash('Sadece takımın danışmanı proje ekleyebilir.', 'danger')
        return redirect(url_for('dashboard'))

    templates = []
    if team.advisor.created_by:
        templates = CompetitionTemplate.query.filter_by(ky_creator_id=team.advisor.created_by.id).order_by(CompetitionTemplate.name).all()

    templates_with_details = {}
    for tpl in templates:
        try:
            data = json.loads(tpl.topics_themes_json) if tpl.topics_themes_json else {}
            templates_with_details[tpl.id] = {
            'name': tpl.name, 
                'topics': data.get('topics', []),
                'common_themes': data.get('common_themes', [])
        }
        except json.JSONDecodeError:
            templates_with_details[tpl.id] = {'name': tpl.name, 'topics': [], 'common_themes': []}

    if request.method == 'POST':
        project_name = request.form.get('project_name')
        project_description = request.form.get('project_description')
        template_id_str = request.form.get('competition_template_id')
        main_topic = request.form.get('main_topic')
        common_sub_theme = request.form.get('common_sub_theme')

        if not all([project_name, project_description, template_id_str]):
            flash('Proje adı, açıklaması ve yarışma şablonu seçimi zorunludur.', 'danger')
            return render_template('add_project_to_team.html', team=team, templates=templates, templates_with_details_json=json.dumps(templates_with_details), form_data=request.form)

        new_project = Project(
            name=project_name,
            description=project_description,
            team_id=team.id,
            creator_id=current_user.id,
            competition_template_id=int(template_id_str),
            main_topic=main_topic if main_topic else None,
            common_sub_theme=common_sub_theme if common_sub_theme else None
        )
        db.session.add(new_project)

        template = CompetitionTemplate.query.get(int(template_id_str))
        if template and template.requires_meg_approval:
            new_project.meg_approval_status = 'İzin Beklemede'

        if template:
            for defined_date in template.defined_dates:
                timeline_event = TimelineEvent(
                    date=defined_date.date,
                    description=defined_date.name,
                    project=new_project,
                    is_from_template=True,
                    competition_template_date_id=defined_date.id
                )
                db.session.add(timeline_event)

        db.session.commit()
        flash(f'"{project_name}" projesi başarıyla oluşturuldu!', 'success')
        return redirect(url_for('project_detail', project_id=new_project.id))

    return render_template('add_project_to_team.html', team=team, templates=templates, templates_with_details_json=json.dumps(templates_with_details), form_data={})

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash('Bu sayfaya erişim yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('admin_panel.html')

@app.route('/admin/add_kurum_yoneticisi', methods=['GET', 'POST'])
@login_required
def add_kurum_yoneticisi():
    if not current_user.is_admin:
        flash('Bu işlemi yapmaya yetkiniz yok.', 'danger')
        return redirect(url_for('admin_panel'))

    if request.method == 'POST':
        username = request.form.get('username')
        email_input = request.form.get('email')
        password = request.form.get('password')

        if not username or not password or not email_input:
            flash('Kullanıcı adı, e-posta ve şifre gereklidir.', 'danger')
            return render_template('add_kurum_yoneticisi.html', username=username, email=email_input)

        try:
            valid_email = validate_email(email_input, check_deliverability=False)
            normalized_email = valid_email.normalized
        except EmailNotValidError as e:
            flash(f"Geçersiz e-posta adresi: {str(e)}", 'danger')
            return render_template('add_kurum_yoneticisi.html', username=username, email=email_input)

        existing_user_username = User.query.filter_by(username=username).first()
        if existing_user_username:
            flash("Bu kullanıcı adı zaten mevcut.", 'danger')
            return render_template('add_kurum_yoneticisi.html', username=username, email=email_input)
        
        existing_user_email = User.query.filter_by(email=normalized_email).first()
        if existing_user_email:
            flash("Bu e-posta adresi zaten kullanılıyor.", 'danger')
            return render_template('add_kurum_yoneticisi.html', username=username, email=email_input)

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        verification_token = str(uuid.uuid4())
        
        new_ky_user = User(
            username=username, 
            email=normalized_email, 
            password_hash=hashed_password, 
            role='kurum_yoneticisi',
            email_verification_token=verification_token,
            email_verified=False
        )
        
        try:
            db.session.add(new_ky_user)
            db.session.commit()
            send_verification_email(new_ky_user)
            flash(f"Kurum Yöneticisi '{username}' başarıyla oluşturuldu! Hesabını doğrulaması için e-posta gönderildi.", 'success')
            return redirect(url_for('admin_panel'))
        except Exception as e:
            db.session.rollback()
            flash(f"Kurum Yöneticisi oluşturulurken bir hata oluştu: {str(e)}", 'danger')
            print(f"Error creating Kurum Yöneticisi by admin {current_user.username}: {e}")
            return render_template('add_kurum_yoneticisi.html', username=username, email=email_input)

    return render_template('add_kurum_yoneticisi.html')

@app.route('/admin/manage_users')
@login_required
def manage_users():
    if not current_user.is_admin:
        flash('Bu sayfaya erişim yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))
    
    users = User.query.filter(User.id != current_user.id).order_by(User.username).all()
    return render_template('manage_users.html', users=users)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Bu işlemi yapmaya yetkiniz yok.', 'danger')
        return redirect(url_for('admin_panel'))

    if user_id == current_user.id:
        flash('Kendinizi silemezsiniz.', 'danger')
        return redirect(url_for('manage_users'))

    user_to_delete = User.query.get(user_id)

    if user_to_delete:
        try:
            if user_to_delete.is_teacher or user_to_delete.is_kurum_yoneticisi:
                if Team.query.filter_by(advisor_id=user_to_delete.id).first():
                    flash(f'{user_to_delete.username} bir takımın danışmanı olduğu için silinemez. Önce danışmanlığını devredin.', 'danger')
                    return redirect(url_for('manage_users'))
            
            for team in user_to_delete.member_of_teams:
                team.members.remove(user_to_delete)

            db.session.delete(user_to_delete)
            db.session.commit()
            flash(f'Kullanıcı {user_to_delete.username} başarıyla silindi.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Kullanıcı silinirken bir hata oluştu: {str(e)}', 'danger')
            print(f"Error deleting user {user_id} by admin {current_user.username}: {e}")
    else:
        flash('Silinecek kullanıcı bulunamadı.', 'warning')
    
    return redirect(url_for('manage_users'))

@app.route('/admin/user/<int:user_id>/details')
@login_required
def admin_view_user_details(user_id):
    if not current_user.is_admin:
        flash('Bu sayfaya erişim yetkiniz yok.', 'danger')
        return redirect(url_for('admin_panel'))

    viewed_user = User.query.get_or_404(user_id)
    
    member_of_teams = viewed_user.member_of_teams
    advised_teams_with_students = []

    if viewed_user.is_teacher or viewed_user.is_kurum_yoneticisi:
        raw_advised_teams = Team.query.filter_by(advisor_id=viewed_user.id).all()
        for team in raw_advised_teams:
            students_in_team = [member for member in team.members if member.role == 'student']
            advised_teams_with_students.append({'team': team, 'students': students_in_team})

    user_team_ids = set()
    for team_info in advised_teams_with_students:
        user_team_ids.add(team_info['team'].id)
    for team in member_of_teams:
        user_team_ids.add(team.id)

    user_projects = []
    if user_team_ids:
        user_projects = Project.query.filter(Project.team_id.in_(list(user_team_ids))).order_by(Project.created_at.desc()).all()

    return render_template('admin_user_details.html',
                           viewed_user=viewed_user,
                           member_of_teams=member_of_teams,
                           advised_teams_with_students=advised_teams_with_students,
                           user_projects=user_projects)

@app.route('/kurum_yoneticisi_panel')
@login_required
@kurum_yoneticisi_required
def kurum_yoneticisi_panel():
    return render_template('kurum_yoneticisi_panel.html')

@app.route('/kurum_yoneticisi_panel/projects')
@login_required
def ky_projects():
    if not current_user.is_kurum_yoneticisi:
        flash('Bu sayfaya erişim yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))

    teachers = User.query.filter_by(creator_id=current_user.id, role='teacher').all()
    teacher_ids = [teacher.id for teacher in teachers]

    if not teacher_ids:
        return render_template('ky_projects.html', projects_data=[], filters={})

    projects_query = Project.query.join(Team).filter(Team.advisor_id.in_(teacher_ids))

    filter_by = request.args.get('filter_by')
    filter_query = request.args.get('filter_query', '').strip()

    if filter_by and filter_query:
        if filter_by == 'application_id':
            projects_query = projects_query.filter(Project.application_id.ilike(f'%{filter_query}%'))
        elif filter_by == 'project_name':
            projects_query = projects_query.filter(Project.name.ilike(f'%{filter_query}%'))
        elif filter_by == 'advisor_name':
            projects_query = projects_query.join(User, Team.advisor_id == User.id).filter(User.username.ilike(f'%{filter_query}%'))
        elif filter_by == 'competition_name':
            projects_query = projects_query.join(CompetitionTemplate).filter(CompetitionTemplate.name.ilike(f'%{filter_query}%'))
        elif filter_by == 'main_topic':
            projects_query = projects_query.filter(Project.main_topic.ilike(f'%{filter_query}%'))
        elif filter_by == 'sub_theme':
            projects_query = projects_query.filter(Project.common_sub_theme.ilike(f'%{filter_query}%'))
        elif filter_by == 'student_name':
            projects_query = projects_query.join(team_member_association, Team.id == team_member_association.c.team_id).join(User, User.id == team_member_association.c.user_id).filter(User.role == 'student', User.username.ilike(f'%{filter_query}%'))
        elif filter_by == 'student_class':
             projects_query = projects_query.join(team_member_association, Team.id == team_member_association.c.team_id).join(User, User.id == team_member_association.c.user_id).join(StudentInfo, User.id == StudentInfo.user_id).filter(StudentInfo.student_class.ilike(f'%{filter_query}%'))

    filtered_projects = projects_query.order_by(Project.created_at.desc()).distinct().all()

    projects_data = []
    for project in filtered_projects:
        students = [member for member in project.team.members if member.role == 'student']
        student_names = [student.username for student in students]
        
        student_ids = [student.id for student in students]
        student_infos = StudentInfo.query.filter(StudentInfo.user_id.in_(student_ids)).all()
        student_classes = sorted(list(set([info.student_class for info in student_infos])))

        project_info = {
            'id': project.id,
            'application_id': project.application_id or "Belirtilmemiş",
            'name': project.name,
            'students': ", ".join(student_names) if student_names else "Öğrenci Atanmamış",
            'advisor': project.team.advisor.username if project.team.advisor else "N/A",
            'classes': ", ".join(student_classes) if student_classes else "Belirtilmemiş",
            'competition_name': project.competition_template.name if project.competition_template else "Yok",
            'main_topic': project.main_topic or "Belirtilmemiş",
            'sub_theme': project.common_sub_theme or "Belirtilmemiş",
            'status': "Tamamlandı" if project.is_completed else f"Devam Ediyor ({project.progress}%)",
        }
        projects_data.append(project_info)
    
    return render_template('ky_projects.html', projects_data=projects_data, filters=request.args)

@app.route('/kurum_yoneticisi_panel/add_teacher', methods=['GET', 'POST'])
@login_required
def ky_add_teacher():
    if not current_user.is_kurum_yoneticisi:
        flash('Bu işlemi yapmaya yetkiniz yok.', 'danger')
        return redirect(url_for('kurum_yoneticisi_panel'))

    if request.method == 'POST':
        username = request.form.get('username')
        email_input = request.form.get('email')
        password = request.form.get('password')

        if not username or not password or not email_input:
            flash('Kullanıcı adı, e-posta ve şifre gereklidir.', 'danger')
            return render_template('ky_add_teacher.html', username=username, email=email_input)

        try:
            valid_email = validate_email(email_input, check_deliverability=False)
            normalized_email = valid_email.normalized
        except EmailNotValidError as e:
            flash(f"Geçersiz e-posta adresi: {str(e)}", 'danger')
            return render_template('ky_add_teacher.html', username=username, email=email_input)

        existing_user_username = User.query.filter_by(username=username).first()
        if existing_user_username:
            flash("Bu kullanıcı adı zaten mevcut.", 'danger')
            return render_template('ky_add_teacher.html', username=username, email=email_input)
        
        existing_user_email = User.query.filter_by(email=normalized_email).first()
        if existing_user_email:
            flash("Bu e-posta adresi zaten kullanılıyor.", 'danger')
            return render_template('ky_add_teacher.html', username=username, email=email_input)

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        verification_token = str(uuid.uuid4())
        
        new_teacher = User(
            username=username, 
            email=normalized_email, 
            password_hash=hashed_password, 
            role='teacher',
            email_verification_token=verification_token,
            email_verified=False,
            creator_id=current_user.id
        )
        
        try:
            db.session.add(new_teacher)
            db.session.commit()
            send_verification_email(new_teacher)
            flash(f"Danışman Öğretmen '{username}' başarıyla oluşturuldu! Hesabını doğrulaması için e-posta gönderildi.", 'success')
            return redirect(url_for('kurum_yoneticisi_panel'))
        except Exception as e:
            db.session.rollback()
            flash(f"Danışman Öğretmen oluşturulurken bir hata oluştu: {str(e)}", 'danger')
            print(f"Error creating Teacher by KY {current_user.username}: {e}")
            return render_template('ky_add_teacher.html', username=username, email=email_input)

    return render_template('ky_add_teacher.html')

@app.route('/kurum_yoneticisi_panel/manage_teachers')
@login_required
def ky_manage_teachers():
    if not current_user.is_kurum_yoneticisi:
        flash('Bu sayfaya erişim yetkiniz yok.', 'danger')
        return redirect(url_for('kurum_yoneticisi_panel'))
    
    teachers = User.query.filter_by(creator_id=current_user.id, role='teacher').order_by(User.username).all()
    return render_template('ky_manage_teachers.html', teachers=teachers)

@app.route('/kurum_yoneticisi_panel/reports')
@login_required
def ky_reports():
    if not current_user.is_kurum_yoneticisi:
        flash('Bu sayfaya erişim yetkiniz yok.', 'danger')
        return redirect(url_for('kurum_yoneticisi_panel'))
    return render_template('ky_reports.html')

@app.route('/kurum_yoneticisi_panel/teacher/<int:teacher_id>/details')
@login_required
def ky_view_teacher_details(teacher_id):
    if not current_user.is_kurum_yoneticisi:
        flash('Bu sayfaya erişim yetkiniz yok.', 'danger')
        return redirect(url_for('kurum_yoneticisi_panel'))

    teacher = User.query.get_or_404(teacher_id)

    if not teacher.role == 'teacher':
        flash('Bu kullanıcı bir öğretmen değil.', 'warning')
        return redirect(url_for('ky_manage_teachers'))

    advised_teams_with_students = []
    raw_advised_teams = Team.query.filter_by(advisor_id=teacher.id).all()
    for team in raw_advised_teams:
        students_in_team = [member for member in team.members if member.role == 'student']
        advised_teams_with_students.append({'team': team, 'students': students_in_team})
    
    team_ids = [team_info['team'].id for team_info in advised_teams_with_students]
    teacher_projects = []
    if team_ids:
        teacher_projects = Project.query.filter(Project.team_id.in_(team_ids)).order_by(Project.created_at.desc()).all()

    return render_template('ky_teacher_details.html',
                           viewed_teacher=teacher,
                           advised_teams_with_students=advised_teams_with_students,
                           teacher_projects=teacher_projects)

@app.route('/kurum_yoneticisi_panel/add_competition_template', methods=['GET', 'POST'])
@login_required
def ky_add_competition_template():
    if not current_user.is_kurum_yoneticisi:
        flash('Bu işlemi yapmaya yetkiniz yok.', 'danger')
        return redirect(url_for('kurum_yoneticisi_panel'))

    if request.method == 'POST':
        name = request.form.get('name')
        requires_meg_approval = 'requires_meg_approval' in request.form
        topics_themes_data_json = request.form.get('topics_themes_json')

        if not name:
            flash('Yarışma şablonu adı gereklidir.', 'danger')
            return render_template('ky_add_competition_template.html', form_data=request.form)

        if topics_themes_data_json:
            try:
                json.loads(topics_themes_data_json)
            except json.JSONDecodeError:
                flash('Ana konular/alt temalar için geçersiz JSON formatı.', 'danger')
                return render_template('ky_add_competition_template.html', form_data=request.form)
        else:
            topics_themes_data_json = None

        new_template = CompetitionTemplate(
            name=name,
            requires_meg_approval=requires_meg_approval,
            topics_themes_json=topics_themes_data_json,
            ky_creator_id=current_user.id
        )
        
        saved_document_files = []

        try:
            db.session.add(new_template)
            db.session.flush()

            i = 0
            while True:
                date_name = request.form.get(f'defined_date_name_{i}')
                date_value_str = request.form.get(f'defined_date_value_{i}')
                if date_name is None or date_value_str is None:
                    break
                if not date_name.strip() or not date_value_str.strip():
                    i += 1
                    continue
                
                try:
                    date_obj = datetime.strptime(date_value_str, '%Y-%m-%d').date()
                    template_date = CompetitionTemplateDate(
                        name=date_name.strip(), 
                        date=date_obj, 
                        template=new_template
                    )
                    db.session.add(template_date)
                except ValueError:
                    flash(f'\'{date_name}\' için geçersiz tarih formatı. YYYY-AA-GG kullanın.', 'warning')
                    raise ValueError("Invalid date format")
                i += 1

            doc_template_base_dir = os.path.join(app.config['UPLOAD_FOLDER'], COMPETITION_TEMPLATE_DOCS_FOLDER)
            if not os.path.exists(doc_template_base_dir):
                os.makedirs(doc_template_base_dir)
            
            template_specific_docs_dir = os.path.join(doc_template_base_dir, str(new_template.id))
            if not os.path.exists(template_specific_docs_dir):
                os.makedirs(template_specific_docs_dir)

            j = 0
            while True:
                display_name = request.form.get(f'doc_display_name_{j}')
                file_key = f'doc_file_{j}'
                
                if display_name is None and file_key not in request.files:
                     break
                
                doc_file = request.files.get(file_key)

                if not display_name or not display_name.strip():
                    if doc_file and doc_file.filename:
                        flash(f'{j+1}. döküman için bir görünen ad belirtmelisiniz.', 'warning')
                        raise ValueError("Missing document display name")
                    j += 1
                    continue
                
                if doc_file and doc_file.filename != '':
                    original_filename = secure_filename(doc_file.filename)
                    final_filename = f"{uuid.uuid4()}_{original_filename}"
                    file_path_on_disk = os.path.join(template_specific_docs_dir, final_filename)
                    
                    try:
                        doc_file.save(file_path_on_disk)
                        saved_document_files.append(file_path_on_disk)
                        
                        template_doc = CompetitionTemplateDocument(
                            display_name=display_name.strip(),
                            filename=final_filename,
                            template=new_template
                        )
                        db.session.add(template_doc)
                    except Exception as e_save:
                        flash(f'{display_name} dosyası kaydedilirken hata oluştu: {e_save}', 'danger')
                        raise
                elif doc_file and doc_file.filename != '':
                    flash(f'{display_name} için geçersiz dosya türü.', 'danger')
                    raise ValueError("Invalid file type for document")
                elif not doc_file or doc_file.filename == '':
                    pass 

                j += 1
           
            db.session.commit()
            flash(f'\'{name}\' yarışma şablonu başarıyla oluşturuldu/güncellendi.', 'success')
            return redirect(url_for('ky_manage_competition_templates'))

        except Exception as e:
            db.session.rollback()
            for file_path in saved_document_files:
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except OSError as ose_clean:
                        app.logger.error(f"Error cleaning up file {file_path} after DB rollback: {ose_clean}")
            if new_template and new_template.id and os.path.exists(template_specific_docs_dir):
                if not os.listdir(template_specific_docs_dir):
                    try:
                        os.rmdir(template_specific_docs_dir)
                    except OSError as ose_rmdir:
                         app.logger.error(f"Error removing empty template doc dir {template_specific_docs_dir}: {ose_rmdir}")
            
            flash(f'Yarışma şablonu oluşturulurken bir hata oluştu: {str(e)}', 'danger')
            app.logger.error(f"Error in ky_add_competition_template: {e}", exc_info=True)
            return render_template('ky_add_competition_template.html', form_data=request.form)

    return render_template('ky_add_competition_template.html', form_data={})

@app.route('/kurum_yoneticisi_panel/manage_competition_templates')
@login_required
def ky_manage_competition_templates():
    if not current_user.is_kurum_yoneticisi:
        flash('Bu sayfaya erişim yetkiniz yok.', 'danger')
        return redirect(url_for('kurum_yoneticisi_panel'))
    
    raw_templates = CompetitionTemplate.query.filter_by(ky_creator_id=current_user.id).order_by(CompetitionTemplate.name).all()
    
    templates_for_display = []
    for tpl in raw_templates:
        parsed_topics = []
        parsed_common_themes = []
        if tpl.topics_themes_json:
            try:
                data = json.loads(tpl.topics_themes_json)
                parsed_topics = data.get('topics', [])
                parsed_common_themes = data.get('common_themes', [])
            except json.JSONDecodeError:
                app.logger.error(f"Could not parse topics_themes_json for template ID {tpl.id}: {tpl.topics_themes_json}")
        
        templates_for_display.append({
            'id': tpl.id,
            'name': tpl.name,
            'requires_meg_approval': tpl.requires_meg_approval,
            'created_at': tpl.created_at,
            'topics': parsed_topics,
            'common_themes': parsed_common_themes,
            'defined_dates': list(tpl.defined_dates.all()),
            'defined_documents': list(tpl.defined_documents.all())
        })

    return render_template('ky_manage_competition_templates.html', templates=templates_for_display)

@app.route('/kurum_yoneticisi_panel/edit_competition_template/<int:template_id>', methods=['GET', 'POST'])
@login_required
def ky_edit_competition_template(template_id):
    if not current_user.is_kurum_yoneticisi:
        flash('Bu işlemi yapmaya yetkiniz yok.', 'danger')
        return redirect(url_for('kurum_yoneticisi_panel'))

    template_to_edit = CompetitionTemplate.query.filter_by(id=template_id, ky_creator_id=current_user.id).first_or_404()
    
    template_doc_base_dir = os.path.join(app.config['UPLOAD_FOLDER'], COMPETITION_TEMPLATE_DOCS_FOLDER)
    template_specific_docs_dir = os.path.join(template_doc_base_dir, str(template_to_edit.id))

    if request.method == 'POST':
        template_to_edit.name = request.form.get('name')
        template_to_edit.requires_meg_approval = 'requires_meg_approval' in request.form
        
        topics_themes_data_json = request.form.get('topics_themes_json')
        if topics_themes_data_json:
            try:
                json.loads(topics_themes_data_json)
                template_to_edit.topics_themes_json = topics_themes_data_json
            except json.JSONDecodeError:
                flash('Ana konular/alt temalar için geçersiz JSON formatı. Değişiklikler bu alan için kaydedilmedi.', 'warning')
        else:
            template_to_edit.topics_themes_json = None

        saved_document_files_during_edit = []
        try:
            existing_date_ids_in_db = {str(d.id) for d in template_to_edit.defined_dates}
            submitted_existing_date_ids = set()

            idx = 0
            while True:
                date_id = request.form.get(f'date_id_{idx}')
                print(date_id)
                print()
                if date_id is None:
                    break
                submitted_existing_date_ids.add(date_id)

                date_name = request.form.get(f'date_name_{idx}') or request.form.get(f'defined_date_name_{idx}')
                date_value_str = request.form.get(f'date_value_{idx}') or request.form.get(f'defined_date_value_{idx}')
                print(date_name, date_value_str)
                date_to_update = CompetitionTemplateDate.query.get(int(date_id))
                print(date_to_update)
                print("mer")
                if date_to_update and date_to_update.competition_template_id == template_to_edit.id:
                    if date_name != None and date_value_str != None:
                        print("burada")
                        try:
                            date_to_update.name = date_name.strip()
                            date_to_update.date = datetime.strptime(date_value_str, '%Y-%m-%d').date()
                        except ValueError:
                            flash(f'{date_name} için geçersiz tarih formatı. YYYY-AA-GG kullanın.', 'warning')
                    else:
                         pass
                else:
                    if not date_name is None or not date_value_str is None:
                        try:
                            date_obj = datetime.strptime(date_value_str, '%Y-%m-%d').date()
                            template_date = CompetitionTemplateDate(
                                name=date_name.strip(), 
                                date=date_obj, 
                                template=template_to_edit
                            )
                            db.session.add(template_date)
                        except ValueError:
                            flash(f'\'{date_name}\' için geçersiz tarih formatı. YYYY-AA-GG kullanın.', 'warning')
                            raise ValueError("Invalid date format")
                idx += 1
            
            date_ids_to_delete = existing_date_ids_in_db - submitted_existing_date_ids
            for del_id_str in date_ids_to_delete:
                date_to_delete = CompetitionTemplateDate.query.get(int(del_id_str))
                if date_to_delete: db.session.delete(date_to_delete)


            if not os.path.exists(template_specific_docs_dir):
                os.makedirs(template_specific_docs_dir)

            existing_doc_ids_in_db = {str(d.id) for d in template_to_edit.defined_documents}
            submitted_existing_doc_ids = set()
            doc_paths_to_delete_on_success = []

            idx = 0
            while True:
                doc_id_str = request.form.get(f'doc_id_{idx}')
                if doc_id_str is None: break
                submitted_existing_doc_ids.add(doc_id_str)

                doc_to_update = CompetitionTemplateDocument.query.get(int(doc_id_str))
                if not (doc_to_update and doc_to_update.competition_template_id == template_to_edit.id):
                    idx += 1
                    continue

                should_remove_doc = request.form.get(f'doc_remove_{idx}') == '1'
                display_name = request.form.get(f'doc_display_name_{idx}')
                doc_file = request.files.get(f'doc_file_{idx}')

                if should_remove_doc:
                    if doc_to_update.filename:
                        old_file_path = os.path.join(template_specific_docs_dir, doc_to_update.filename)
                        doc_paths_to_delete_on_success.append(old_file_path)
                    db.session.delete(doc_to_update)
                else:
                    if display_name and display_name.strip():
                        doc_to_update.display_name = display_name.strip()
                    
                    if doc_file and doc_file.filename != '':
                        if not allowed_file(doc_file.filename):
                            flash(f'{doc_file.filename} için geçersiz dosya türü. Bu döküman güncellenmedi.', 'warning')
                        else:
                            if doc_to_update.filename:
                                old_file_path = os.path.join(template_specific_docs_dir, doc_to_update.filename)
                                if os.path.exists(old_file_path):
                                     doc_paths_to_delete_on_success.append(old_file_path)
                            
                            original_filename = secure_filename(doc_file.filename)
                            new_filename = f"{uuid.uuid4()}_{original_filename}"
                            new_file_path_on_disk = os.path.join(template_specific_docs_dir, new_filename)
                            doc_file.save(new_file_path_on_disk)
                            saved_document_files_during_edit.append(new_file_path_on_disk)
                            doc_to_update.filename = new_filename
                idx += 1
            
            doc_ids_to_delete_implicitly = existing_doc_ids_in_db - submitted_existing_doc_ids
            for del_id_str in doc_ids_to_delete_implicitly:
                doc_to_delete = CompetitionTemplateDocument.query.get(int(del_id_str))
                if doc_to_delete:
                    if doc_to_delete.filename:
                        old_file_path = os.path.join(template_specific_docs_dir, doc_to_delete.filename)
                        doc_paths_to_delete_on_success.append(old_file_path)
                    db.session.delete(doc_to_delete)

            new_doc_idx = 0
            while True:
                new_doc_display_name = request.form.get(f'new_doc_display_name_{new_doc_idx}')
                new_doc_file = request.files.get(f'new_doc_file_{new_doc_idx}')
                if new_doc_display_name is None and new_doc_file is None:
                    break
                if new_doc_display_name and new_doc_display_name.strip() and new_doc_file and new_doc_file.filename != '':
                    if not allowed_file(new_doc_file.filename):
                        flash(f'{new_doc_file.filename} için geçersiz dosya türü.', 'warning')
                    else:
                        original_filename = secure_filename(new_doc_file.filename)
                        new_filename = f"{uuid.uuid4()}_{original_filename}"
                        new_file_path_on_disk = os.path.join(template_specific_docs_dir, new_filename)
                        new_doc_file.save(new_file_path_on_disk)
                        saved_document_files_during_edit.append(new_file_path_on_disk)
                        template_doc = CompetitionTemplateDocument(
                            display_name=new_doc_display_name.strip(),
                            filename=new_filename,
                            template=template_to_edit
                        )
                        db.session.add(template_doc)
                new_doc_idx += 1

            db.session.commit()
            for file_path in doc_paths_to_delete_on_success:
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except OSError as ose:
                        app.logger.warning(f"Could not delete old document file {file_path}: {ose}")
            if os.path.exists(template_specific_docs_dir) and not os.listdir(template_specific_docs_dir):
                try:
                    os.rmdir(template_specific_docs_dir)
                except OSError as ose_rmdir:
                    app.logger.warning(f"Could not remove empty doc dir {template_specific_docs_dir}: {ose_rmdir}")
            flash(f'"{template_to_edit.name}" yarışma şablonu başarıyla güncellendi.', 'success')
            return redirect(url_for('ky_manage_competition_templates'))

        except Exception as e:
            db.session.rollback()
            for file_path in saved_document_files_during_edit:
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except OSError as ose_clean:
                        app.logger.error(f"Error cleaning up file {file_path} after rollback: {ose_clean}")
            flash(f'Şablon güncellenirken bir hata oluştu: {str(e)}', 'danger')
            app.logger.error(f"Error in ky_edit_competition_template for template {template_id}: {e}", exc_info=True)
            
            parsed_topics = []
            parsed_common_themes = []
            if template_to_edit.topics_themes_json:
                try:
                    data = json.loads(template_to_edit.topics_themes_json)
                    parsed_topics = data.get('topics', [])
                    parsed_common_themes = data.get('common_themes', [])
                except json.JSONDecodeError:
                    app.logger.error(f"Could not parse topics_themes_json for template ID {template_to_edit.id} in POST error handler")
            
            topics_data = {
                'topics': parsed_topics,
                'common_themes': parsed_common_themes
            }
            return render_template('ky_edit_competition_template.html', template=template_to_edit, form_data=request.form, topics_data=topics_data)

    parsed_topics = []
    parsed_common_themes = []
    if template_to_edit.topics_themes_json:
        try:
            data = json.loads(template_to_edit.topics_themes_json)
            parsed_topics = data.get('topics', [])
            parsed_common_themes = data.get('common_themes', [])
        except json.JSONDecodeError:
            app.logger.error(f"Could not parse topics_themes_json for template ID {template_to_edit.id}")

    topics_data = {
        'topics': parsed_topics,
        'common_themes': parsed_common_themes
    }

    return render_template('ky_edit_competition_template.html',
                           template=template_to_edit,
                           topics_data=topics_data,
                           form_data={})

@app.route('/competition_template/<int:template_id>/document/<path:filename>')
@login_required
def serve_competition_template_document(template_id, filename):
    template = CompetitionTemplate.query.get_or_404(template_id)

    if not current_user.is_kurum_yoneticisi and template.ky_creator_id != current_user.id:
        if not current_user.is_teacher or current_user.creator_id != template.ky_creator_id:
            flash('Bu dökümana erişim yetkiniz yok.', 'danger')
            return redirect(url_for('dashboard'))

    doc = CompetitionTemplateDocument.query.filter_by(
        competition_template_id=template_id, filename=filename
    ).first_or_404()

    directory = os.path.join(
        app.config['UPLOAD_FOLDER'], COMPETITION_TEMPLATE_DOCS_FOLDER, str(template_id)
    )

    abs_directory = os.path.abspath(directory)
    abs_upload_folder = os.path.abspath(app.config['UPLOAD_FOLDER'])
    if not abs_directory.startswith(abs_upload_folder):
        flash('Kısıtlanmış dosya yoluna erişim denemesi.', 'danger')
        return redirect(url_for('ky_manage_competition_templates'))

    try:
        return send_from_directory(directory, filename)
    except FileNotFoundError:
        flash('Döküman dosyası sunucuda bulunamadı.', 'warning')
        return redirect(url_for('ky_manage_competition_templates'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    username = request.form.get('username')
    email_input = request.form.get('email')

    if not username or not email_input:
        flash('Kullanıcı adı ve e-posta gereklidir.', 'danger')
        return redirect(url_for('profile'))
    try:
        valid_email = validate_email(email_input, check_deliverability=False)
        normalized_email = valid_email.normalized
    except EmailNotValidError as e:
        flash(f"Geçersiz e-posta adresi: {str(e)}", 'danger')
        return redirect(url_for('profile'))

    existing_user_username = User.query.filter(
        User.username == username, User.id != current_user.id
    ).first()
    if existing_user_username:
        flash("Bu kullanıcı adı zaten kullanımda.", 'danger')
        return redirect(url_for('profile'))

    existing_user_email = User.query.filter(
        User.email == normalized_email, User.id != current_user.id
    ).first()
    if existing_user_email:
        flash("Bu e-posta adresi zaten kullanımda.", 'danger')
        return redirect(url_for('profile'))

    if normalized_email != current_user.email:
        current_user.email_verified = False
        current_user.email_verification_token = str(uuid.uuid4())
        current_user.email = normalized_email
        try:
            send_verification_email(current_user)
            flash("E-posta adresiniz güncellendi. Lütfen yeni adresinizi doğrulamak için e-postanızı kontrol edin.", 'success')
        except Exception as e:
            flash("Doğrulama e-postası gönderilemedi. Lütfen destek ile iletişime geçin.", 'danger')
            print(f"Error sending verification email to {normalized_email}: {e}")

    current_user.username = username
    try:
        db.session.commit()
        flash("Profiliniz başarıyla güncellendi.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f"Profil güncellenirken bir hata oluştu: {str(e)}", 'danger')
        print(f"Error updating profile for user {current_user.id}: {e}")

    return redirect(url_for('profile'))

@app.route('/profile/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if not current_user.password_hash:
        flash("Bu hesap bir OAuth hesabıdır. Şifre değiştirme işlemi OAuth kullanıcıları için geçerli değildir.", 'warning')
        return redirect(url_for('profile'))

    if not bcrypt.check_password_hash(current_user.password_hash, current_password):
        flash("Mevcut şifre yanlış.", 'danger')
        return redirect(url_for('profile'))

    if new_password != confirm_password:
        flash("Yeni şifreler eşleşmiyor.", 'danger')
        return redirect(url_for('profile'))

    if len(new_password) < 6:
        flash("Yeni şifre en az 6 karakter olmalıdır.", 'danger')
        return redirect(url_for('profile'))

    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    current_user.password_hash = hashed_password
    try:
        db.session.commit()
        flash("Şifreniz başarıyla değiştirildi.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f"Şifre değiştirilirken bir hata oluştu: {str(e)}", 'danger')
        print(f"Error changing password for user {current_user.id}: {e}")

    return redirect(url_for('profile'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            if user.oauth_provider:
                flash("Bu hesap bir OAuth hesabıdır. Şifre sıfırlama yerine OAuth sağlayıcınız üzerinden giriş yapmayı deneyin.", 'warning')
                return redirect(url_for('forgot_password'))

            reset_token = str(uuid.uuid4())
            user.email_verification_token = reset_token
            try:
                db.session.commit()
                reset_url = url_for('reset_password', token=reset_token, _external=True)
                subject = "Şifre Sıfırlama Talebi - Proje Yönetim Sistemi"
                html_body = render_template(
                    'email/reset_password.html',
                    username=user.username,
                    reset_url=reset_url
                )
                text_body = (
                    f"Merhaba {user.username},\n\n"
                    f"Şifrenizi sıfırlamak için aşağıdaki bağlantıya tıklayın:\n"
                    f"{reset_url}\n\n"
                    f"Eğer şifre sıfırlama talebinde bulunmadıysanız, lütfen bu e-postayı dikkate almayın."
                )
                msg = Message(subject, recipients=[user.email], body=text_body, html=html_body)
                mail.send(msg)
                flash("Şifre sıfırlama bağlantısı e-posta adresinize gönderildi.", 'success')
            except Exception as e:
                db.session.rollback()
                flash("Şifre sıfırlama e-postası gönderilemedi. Lütfen tekrar deneyin veya destek ile iletişime geçin.", 'danger')
                print(f"Error sending password reset email to {email}: {e}")
        else:
            flash("Bu e-posta adresiyle kayıtlı bir kullanıcı bulunamadı.", 'danger')

        return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    user = User.query.filter_by(email_verification_token=token).first()
    if not user:
        flash("Geçersiz veya süresi dolmuş şifre sıfırlama bağlantısı.", 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash("Şifreler eşleşmiyor.", 'danger')
            return render_template('reset_password.html', token=token)

        if len(new_password) < 6:
            flash("Şifre en az 6 karakter olmalıdır.", 'danger')
            return render_template('reset_password.html', token=token)

        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password_hash = hashed_password
        user.email_verification_token = None
        try:
            db.session.commit()
            flash("Şifreniz başarıyla sıfırlandı. Şimdi giriş yapabilirsiniz.", 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f"Şifre sıfırlanırken bir hata oluştu: {str(e)}", 'danger')
            print(f"Error resetting password for user {user.id}: {e}")
            return render_template('reset_password.html', token=token)

    return render_template('reset_password.html', token=token)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

@app.route('/survey/<token>', methods=['GET', 'POST'])
def survey_page(token):
    project = Project.query.filter_by(survey_token=token).first_or_404()

    if request.method == 'POST':
        name = request.form.get('respondent_name')
        work_results = request.form.get('work_results')
        contribution = request.form.get('contribution')
        suggestions = request.form.get('suggestions')

        if not name or not work_results or not contribution:
            flash('Lütfen Ad, Çalışma Sonuçları ve Katkı alanlarını doldurun.', 'danger')
            return render_template('survey.html', project=project)

        response = SurveyResponse(
            project_id=project.id,
            respondent_name=name,
            work_results_feedback=work_results,
            contribution_feedback=contribution,
            suggestions_feedback=suggestions
        )
        db.session.add(response)
        db.session.commit()
        return render_template('survey_thanks.html', project_name=project.name)

    return render_template('survey.html', project=project)

def send_survey_email(user_email, user_name, project_name, survey_url):
    subject = f"Proje Tamamlandı: '{project_name}' için Geri Bildiriminiz"
    html_body = render_template('email/survey_notification.html',
                                username=user_name,
                                project_name=project_name,
                                survey_url=survey_url)
    msg = Message(subject, recipients=[user_email], html=html_body)
    try:
        mail.send(msg)
        print(f"Survey email sent to {user_email}")
    except Exception as e:
        print(f"Error sending survey email to {user_email}: {e}")
        pass

def send_material_request_approval_email(request):
    """Sends an email to the advisor to approve a material request."""
    project = request.project
    advisor = project.team.advisor
    requester = request.requester
    approval_link = url_for('handle_material_request', token=request.approval_token, _external=True)

    msg = Message(
        f"Yeni Malzeme Talebi: {project.name} Projesi",
        sender=app.config['MAIL_USERNAME'],
        recipients=[advisor.email]
    )
    msg.html = f"""
    <p>Merhaba {advisor.username},</p>
    <p>
        <b>{project.name}</b> projesi için <b>{requester.username}</b> tarafından yeni bir malzeme talebi oluşturuldu.
    </p>
    <p>
        Talebi incelemek ve onaylamak/reddetmek için lütfen aşağıdaki bağlantıya tıklayın:
    </p>
    <p>
        <a href="{approval_link}" style="padding: 10px 15px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">
            Talebi Görüntüle
        </a>
    </p>
    <p>
        İsteği görüntüleyemiyorsanız, şu linki tarayıcınıza yapıştırabilirsiniz: {approval_link}
    </p>
    <p>Teşekkürler.</p>
    """
    try:
        mail.send(msg)
        return True
    except Exception as e:
        app.logger.error(f"Material request approval email could not be sent to {advisor.email}: {e}")
        return False

@app.route('/kurum_yoneticisi_panel/project/<int:project_id>/survey_results')
@login_required
def ky_survey_results(project_id):
    project = Project.query.get_or_404(project_id)
    # Authorization check...
    return render_template('ky_survey_results.html', project=project)

# --- Material Management Routes ---

@app.route('/project/<int:project_id>/materials', methods=['GET', 'POST'])
@login_required
def list_materials(project_id):
    project = Project.query.get_or_404(project_id)
    # Authorization: Only student members of the project can request materials.
    if not (current_user in project.team.members and current_user.is_student):
        flash('Sadece projenin öğrenci üyeleri malzeme talebinde bulunabilir.', 'danger')
        return redirect(url_for('project_detail', project_id=project.id))

    if request.method == 'POST':
        cart_data = request.form.get('cart')

        if not cart_data:
            flash('İstek sepetiniz boş olamaz.', 'danger')
            return redirect(url_for('list_materials', project_id=project.id))

        try:
            cart = json.loads(cart_data)
            if not cart:
                flash('İstek sepetiniz boş olamaz.', 'warning')
                return redirect(url_for('list_materials', project_id=project.id))
        except json.JSONDecodeError:
            flash('Geçersiz sepet verisi.', 'danger')
            return redirect(url_for('list_materials', project_id=project.id))

        new_request = MaterialRequest(
            project_id=project.id,
            requester_id=current_user.id
        )
        db.session.add(new_request)
        db.session.flush()

        for item in cart:
            material = Material.query.get(item['id'])
            if material and item['quantity'] > 0:
                request_item = MaterialRequestItem(
                    request_id=new_request.id,
                    material_id=material.id,
                    quantity_requested=item['quantity']
                )
                db.session.add(request_item)

        try:
            db.session.commit()
            # Send approval email to advisor
            if not send_material_request_approval_email(new_request):
                 flash('Onay e-postası gönderilemedi, ancak talep oluşturuldu. Lütfen danışmanınızla iletişime geçin.', 'warning')
            else:
                flash('Malzeme talebiniz başarıyla oluşturuldu ve danışman onayına gönderildi.', 'success')
            return redirect(url_for('project_detail', project_id=project.id))
        except Exception as e:
            db.session.rollback()
            flash(f'Talep oluşturulurken bir hata oluştu: {e}', 'danger')


    materials = Material.query.order_by(Material.category, Material.name).all()
    return render_template('materials.html', materials=materials, project=project)

@app.route('/project/<int:project_id>/request_external_material', methods=['GET', 'POST'])
@login_required
def request_external_material(project_id):
    project = Project.query.get_or_404(project_id)
    # Authorization: Only student members of the project can request materials.
    if not (current_user in project.team.members and current_user.is_student):
        flash('Sadece projenin öğrenci üyeleri malzeme talebinde bulunabilir.', 'danger')
        return redirect(url_for('project_detail', project_id=project.id))

    if request.method == 'POST':
        product_names = request.form.getlist('product_name')
        product_links = request.form.getlist('product_link')
        categories = request.form.getlist('category')
        estimated_prices = request.form.getlist('estimated_price')
        quantities = request.form.getlist('quantity')

        if not any(product_names):
            flash('En az bir malzeme bilgisi girmelisiniz.', 'danger')
            return redirect(url_for('request_external_material', project_id=project_id))

        new_request = ExternalMaterialRequest(
            project_id=project.id,
            requester_id=current_user.id
        )
        db.session.add(new_request)
        
        for i in range(len(product_names)):
            if product_names[i] and categories[i]: # Only add if product name and category are not empty
                new_item = ExternalMaterialRequestItem(
                    request=new_request,
                    product_name=product_names[i],
                    product_link=product_links[i] or None,
                    category=categories[i],
                    estimated_price=float(estimated_prices[i]) if estimated_prices[i] else None,
                    quantity=int(quantities[i]) if quantities[i] else 1
                )
                db.session.add(new_item)
        
        try:
            db.session.commit()
            flash('Stok dışı malzeme talebiniz başarıyla oluşturuldu ve Kurum Yöneticisi onayına gönderildi.', 'success')
            return redirect(url_for('project_detail', project_id=project.id))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error creating external material request: {e}")
            flash(f'Talep oluşturulurken bir hata oluştu: {e}', 'danger')

    return render_template('request_external_material.html', project=project)

@app.route('/handle_material_request/<token>', methods=['GET', 'POST'])
@login_required
def handle_material_request(token):
    req = MaterialRequest.query.filter_by(approval_token=token).first_or_404()
    project = req.project

    # Security check: only the project advisor can access this page
    if current_user.id != project.team.advisor_id:
        flash('Bu talebi işleme yetkiniz yok.', 'danger')
        return redirect(url_for('dashboard'))

    # If request is not pending anymore, just show the status
    if req.status != 'Danışman Onayı Bekliyor':
        flash(f'Bu talep zaten işleme alınmış. Mevcut durum: {req.status}', 'info')
        return redirect(url_for('project_detail', project_id=project.id))

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'approve':
            # Check for stock availability
            for item in req.items:
                if item.material.quantity_in_stock < item.quantity_requested:
                    flash(f"Stok yetersiz: '{item.material.name}' için {item.quantity_requested} adet talep edildi, ancak stokta {item.material.quantity_in_stock} adet var.", 'danger')
                    return redirect(url_for('handle_material_request', token=token))
            
            # Stock is now deducted upon delivery. We just mark as approved here.
            req.status = 'Onaylandı'
            req.advisor_notes = request.form.get('notes')
            flash('Malzeme talebi başarıyla onaylandı. Stok, teslimat sırasında düşülecektir.', 'success')

        elif action == 'reject':
            req.status = 'Reddedildi'
            req.advisor_notes = request.form.get('notes')
            if not req.advisor_notes:
                flash('Lütfen talebi reddetme nedeninizi belirtin.', 'warning')
                return redirect(url_for('handle_material_request', token=token))
            flash('Malzeme talebi reddedildi.', 'info')
        
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f'İşlem sırasında bir hata oluştu: {e}', 'danger')

        return redirect(url_for('project_detail', project_id=project.id))

    return render_template('approve_material_request.html', request=req)

def kurum_yoneticisi_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'kurum_yoneticisi':
            flash('Bu sayfayı görüntüleme yetkiniz yok.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- KY Material Management Routes ---

@app.route('/ky/materials/new', methods=['GET', 'POST'])
@login_required
@kurum_yoneticisi_required
def ky_new_material():
    if request.method == 'POST':
        name = request.form.get('name')
        category = request.form.get('category')
        description = request.form.get('description')
        quantity_in_stock = request.form.get('quantity_in_stock', 0, type=int)

        if not name or not category:
            flash('Malzeme adı ve kategori zorunludur.', 'danger')
            return render_template('ky_new_material.html', form_data=request.form)

        existing_material = Material.query.filter_by(name=name).first()
        if existing_material:
            flash(f'"{name}" adında bir malzeme zaten mevcut.', 'warning')
            return render_template('ky_new_material.html', form_data=request.form)

        new_material = Material(
            name=name,
            category=category,
            description=description,
            quantity_in_stock=quantity_in_stock
        )
        try:
            db.session.add(new_material)
            db.session.commit()
            flash(f'"{name}" malzemesi başarıyla eklendi.', 'success')
            return redirect(url_for('ky_material_list'))
        except Exception as e:
            db.session.rollback()
            flash(f'Malzeme eklenirken bir hata oluştu: {str(e)}', 'danger')
    
    return render_template('ky_new_material.html', form_data={})

@app.route('/ky/materials/list', methods=['GET'])
@login_required
@kurum_yoneticisi_required
def ky_material_list():
    materials = Material.query.order_by(Material.name).all()
    return render_template('ky_material_list.html', materials=materials)

@app.route('/ky/materials/update_stock/<int:material_id>', methods=['POST'])
@login_required
@kurum_yoneticisi_required
def ky_update_stock(material_id):
    material = Material.query.get_or_404(material_id)
    quantity = request.form.get('quantity_in_stock', type=int)

    if quantity is not None and quantity >= 0:
        material.quantity_in_stock = quantity
        db.session.commit()
        flash(f'"{material.name}" stok adedi güncellendi.', 'success')
    else:
        flash('Geçersiz stok adedi.', 'danger')

    return redirect(url_for('ky_material_list'))

@app.route('/ky/materials/move_to_scrap/<int:material_id>', methods=['POST'])
@login_required
@kurum_yoneticisi_required
def ky_move_to_scrap(material_id):
    material = Material.query.get_or_404(material_id)
    quantity_to_scrap = request.form.get('quantity_to_scrap', type=int)

    if quantity_to_scrap is None or quantity_to_scrap <= 0:
        flash('Lütfen hurdaya taşımak için geçerli bir miktar girin.', 'warning')
        return redirect(url_for('ky_material_list'))

    if quantity_to_scrap > material.quantity_in_stock:
        flash(f'Stokta yeterli malzeme yok. Sadece {material.quantity_in_stock} adet hurdaya taşınabilir.', 'warning')
        return redirect(url_for('ky_material_list'))

    material.quantity_in_stock -= quantity_to_scrap
    material.quantity_scrapped += quantity_to_scrap
    db.session.commit()

    flash(f'{quantity_to_scrap} adet "{material.name}" başarıyla hurdaya taşındı.', 'success')
    return redirect(url_for('ky_material_list'))
@app.route('/ky/materials/requests', methods=['GET'])
@login_required
@kurum_yoneticisi_required
def ky_material_requests():
    pending_users_count = 0
    # Query for requests that are approved by the advisor
    requests = MaterialRequest.query.filter_by(status='Onaylandı').order_by(MaterialRequest.request_date.desc()).all()
    return render_template("ky_material_requests.html", requests=requests, pending_users_count=pending_users_count)

@app.route('/ky/materials/request/<int:request_id>/deliver', methods=['GET'])
@login_required
@kurum_yoneticisi_required
def deliver_material_request(request_id):
    material_request = MaterialRequest.query.get_or_404(request_id)
    
    # Allow download if the request is either 'Approved' or already 'Delivered'
    if material_request.status not in ['Onaylandı', 'Teslim Edildi']:
        flash('Sadece onaylanmış veya daha önce teslim edilmiş talepler için tutanak oluşturulabilir.', 'warning')

        # The requester must be a student to have student info
    if not material_request.requester.is_student or not material_request.requester.student_info:
            flash('Talep sahibi öğrenci bilgileri bulunamadı. Bu talep için otomatik tutanak oluşturulamaz.', 'danger')
            return redirect(url_for('ky_material_requests'))
        # Render the HTML template for the PDF
    today_date_str = datetime.now(timezone.utc).strftime('%d.%m.%Y')
    rendered_html = render_template(
        'delivery_receipt.html', 
        request=material_request, 
        today_date=today_date_str,
        current_user=current_user
    )
    
    # Generate PDF
    pdf = HTML(string=rendered_html).write_pdf()

    # Change status to 'Delivered' only if it's currently 'Approved'
    if material_request.status == 'Onaylandı':
        # Check for stock availability before deducting
        for item in material_request.items:
            if item.material.quantity_in_stock < item.quantity_requested:
                flash(f"Stok yetersiz: '{item.material.name}' için {item.quantity_requested} adet talep edildi, ancak stokta {item.material.quantity_in_stock} adet var. Teslimat yapılamadı.", 'danger')
                return redirect(url_for('ky_material_requests'))
        
        # If all items are available, update stock and status
        for item in material_request.items:
            item.material.quantity_in_stock -= item.quantity_requested

        material_request.status = 'Teslim Edildi'
        db.session.commit()
    
    # Create response
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    # Use 'attachment' to force a download dialog, which is more robust for download managers
    response.headers['Content-Disposition'] = f'attachment; filename=teslim_tutanagi_{material_request.id}.pdf'
    
    return response


@app.route('/ky/materials/scrapped', methods=['GET'])
@login_required
@kurum_yoneticisi_required
def ky_scrapped_materials():
    scrapped_materials = Material.query.filter_by(is_scrap=True).order_by(Material.name).all()
    return render_template('ky_scrapped_materials.html', materials=scrapped_materials)

@app.route('/ky/materials/delivered', methods=['GET'])
@login_required
@kurum_yoneticisi_required
def ky_delivered_materials():
    show_processed = request.args.get('show_processed', 'false').lower() == 'true'
    
    query = MaterialRequest.query.filter_by(status='Teslim Edildi')
    
    if not show_processed:
        query = query.filter_by(return_processed=False)
        
    delivered_requests = query.order_by(MaterialRequest.request_date.desc()).all()
    
    return render_template('ky_delivered_materials.html', requests=delivered_requests, show_processed=show_processed)

@app.route('/ky/materials/return/<int:request_id>', methods=['GET', 'POST'])
@login_required
@kurum_yoneticisi_required
def ky_process_return(request_id):
    material_request = MaterialRequest.query.get_or_404(request_id)

    if material_request.return_processed:
        flash('Bu talep için iade işlemi zaten yapılmış.', 'warning')
        return redirect(url_for('ky_delivered_materials'))

    if material_request.status != 'Teslim Edildi':
        flash('Sadece "Teslim Edildi" durumundaki talepler için iade işlemi yapılabilir.', 'warning')
        return redirect(url_for('ky_delivered_materials'))

    if request.method == 'POST':
        try:
            for item in material_request.items:
                returned_working = int(request.form.get(f'returned_working_{item.id}', 0))
                returned_broken = int(request.form.get(f'returned_broken_{item.id}', 0))

                if returned_working < 0 or returned_broken < 0:
                    flash('İade miktarları negatif olamaz.', 'danger')
                    return render_template('ky_process_return.html', material_request=material_request)

                if returned_working + returned_broken > item.quantity_requested:
                    flash(f'"{item.material.name}" için iade edilen toplam miktar, talep edilen miktarı aşamaz.', 'danger')
                    return render_template('ky_process_return.html', material_request=material_request)

                # Update the request item
                item.quantity_returned_working = returned_working
                item.quantity_returned_broken = returned_broken

                # Update material stock
                material = item.material
                material.quantity_in_stock += returned_working
                material.quantity_scrapped += returned_broken
                
            material_request.return_processed = True
            db.session.commit()
            flash(f'Talep #{request_id} için iade işlemi başarıyla tamamlandı.', 'success')
            return redirect(url_for('ky_delivered_materials'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error processing material return for request {request_id}: {e}")
            flash('İade işlemi sırasında bir hata oluştu. Lütfen tekrar deneyin.', 'danger')
    
    return render_template('ky_process_return.html', material_request=material_request)

@app.route('/ky/external_material_requests', methods=['GET'])
@login_required
@kurum_yoneticisi_required
def ky_external_material_requests():
    # 'status' argümanına göre filtrele, varsayılan olarak 'Beklemede' olanları göster
    status_filter = request.args.get('status', 'Beklemede')
    
    query = ExternalMaterialRequest.query
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
        
    requests = query.order_by(ExternalMaterialRequest.request_date.desc()).all()
    
    return render_template('ky_external_material_requests.html', requests=requests, current_filter=status_filter)

@app.route('/ky/external_material_requests/<int:request_id>/process', methods=['POST'])
@login_required
@kurum_yoneticisi_required
def ky_process_external_request(request_id):
    req = ExternalMaterialRequest.query.get_or_404(request_id)
    action = request.form.get('action')
    notes = request.form.get('ky_notes')

    if action == 'approve':
        req.status = 'Onaylandı'
        
        # Stok dışı talebi onayla ve malzemeleri stoğa ekle
        for item in req.items:
            # Malzemenin stokta olup olmadığını kontrol et (case-insensitive)
            material = Material.query.filter(db.func.lower(Material.name) == db.func.lower(item.product_name)).first()
            if material:
                # Varsa, stok miktarını güncelle
                material.quantity_in_stock += item.quantity
            else:
                # Yoksa, yeni bir malzeme olarak ekle
                new_material = Material(
                    name=item.product_name,
                    category=item.category,
                    description=f"'{req.project.name}' projesi için dışarıdan temin edildi.",
                    quantity_in_stock=item.quantity
                )
                db.session.add(new_material)
        
        flash(f"Talep #{req.id} başarıyla onaylandı ve malzemeler stoğa eklendi.", "success")
    elif action == 'reject':
        if not notes:
            flash("Talebi reddetmek için bir neden belirtmelisiniz.", "danger")
            return redirect(url_for('ky_external_material_requests'))
        req.status = 'Reddedildi'
        flash(f"Talep #{req.id} reddedildi.", "info")
    else:
        flash("Geçersiz işlem.", "warning")
        return redirect(url_for('ky_external_material_requests'))

    req.ky_notes = notes
    db.session.commit()
    return redirect(url_for('ky_external_material_requests'))

@app.route('/device_recog')
@login_required
def device_recog():
    return render_template('device_recog.html')

@app.route('/recognize_device', methods=['POST'])
@login_required
def recognize_device():
    if not GEMINI_API_KEY:
        return jsonify({'error': 'API anahtarı yapılandırılmamış.'}), 500

    if 'image' not in request.files:
        return jsonify({'error': 'Görüntü dosyası bulunamadı.'}), 400

    image_file = request.files['image']
    
    try:
        image = Image.open(image_file.stream)
        
        model = genai.GenerativeModel("gemini-1.5-flash")
        
        # Malzeme listesini veritabanından dinamik olarak çek.
        # Önce kategorisinde 'elektronik' geçenleri dene.
        materials = Material.query.filter(Material.category.ilike('%elektronik%')).order_by(Material.name).all()
        
        # Eğer elektronik kategorisinde malzeme bulunamazsa, tüm malzemeleri al.
        if not materials:
            app.logger.warning("No materials found in 'elektronik' category. Falling back to all materials for recognition.")
            materials = Material.query.order_by(Material.name).all()

        # Veritabanında hiç malzeme yoksa hata döndür.
        if not materials:
            return jsonify({'error': 'Veritabanında tanımlanacak malzeme bulunamadı.'}), 500
            
        material_names = [material.name for material in materials]
        
        prompt_header = "Bu parçanın adını ver. Sadece adını yaz! Aşağıdaki listeyi kullan, listede yoksa veya emin değilsen \"None\" gönder:\n"
        recognition_list = prompt_header + "\n".join(material_names)

        response = model.generate_content([
            image,
            recognition_list
        ])

        # Gemini'dan gelen yanıtı temizleyelim
        result_text = response.text.strip()

        return jsonify({'result': result_text})

    except Exception as e:
        app.logger.error(f"Gemini API Error: {e}")
        return jsonify({'error': f'Malzeme tanıma sırasında bir hata oluştu: {str(e)}'}), 500

if __name__ == '__main__':
    with app.app_context():
        create_tables()
    app.run(host='0.0.0.0',debug=True)

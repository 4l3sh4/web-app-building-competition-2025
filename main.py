from flask import Flask, render_template, url_for, redirect, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, RadioField, TextAreaField, SelectField
from wtforms.validators import InputRequired, Length, ValidationError, Email
from flask_wtf.file import FileField, FileAllowed
from flask_bcrypt import Bcrypt
from datetime import datetime
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'TripleABattery'
app.config['UPLOAD_FOLDER'] = 'static/uploads/pfp'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['MENTORSHIP_DOCUMENTS'] = os.path.join('static', 'uploads', 'mentorship_docs')
os.makedirs(app.config['MENTORSHIP_DOCUMENTS'], exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# ---------------------
# MODELS
# ---------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'student' or 'mentor'

    # one-to-one relationships
    student_profile = db.relationship('StudentProfile', backref='user', uselist=False)
    mentor_profile = db.relationship('MentorProfile', backref='user', uselist=False)

FACULTIES = [
    ('fci', 'Faculty of Computing & Informatics (FCI)'),
    ('faie', 'Faculty of Artificial Intelligence & Engineering (FAIE)'),
    ('fist', 'Faculty of Information Science & Technology (FIST)'),
    ('fet', 'Faculty of Engineering & Technology (FET)'),
]

PROGRAMME_LABELS = {
    'fci': [
        ('bcs', 'Bachelor of Computer Science (Hons.)'),
        ('bit', 'Bachelor of Information Technology (Hons.)'),
        ('dit', 'Diploma in Information Technology'),
    ],

    'faie': [
        ('be', 'Bachelor of Engineering (Hons.)'),
        ('bs', 'Bachelor of Science (Hons.)'),
    ],

    'fist': [
        ('bcs', 'Bachelor of Computer Science (Hons.)'),
        ('bit', 'Bachelor of Information Technology (Hons.)'),
        ('bs', 'Bachelor of Science (Hons.) Bioinformatics'),
        ('dit', 'Diploma in Information Technology'),
    ],

    'fet': [
        ('be', 'Bachelor of Engineering (Hons.)'),
        ('bee', 'Bachelor of Electronics Engineering (Hons.) (Robotics & Automation)'),
        ('bme', 'Bachelor of Mechanical Engineering (Hons.)'),
        ('dee', 'Diploma in Electronic Engineering'),
        ('dme', 'Diploma in Mechanical Engineering'),
    ],
}

SPECIALIZATION_CHOICES = {
    'fci': {
        'bcs': [
            ('cyber', 'Cybersecurity'),
            ('se', 'Software Engineering'),
            ('ds', 'Data Science'),
            ('game', 'Game Development'),
        ],
        'bit': [
            ('is', 'Information Systems'),
        ],
    },
    'faie': {
        'be': [
            ('electrical', 'Electrical'),
            ('electronics', 'Electronics'),
            ('telecomm', 'Electronic majoring in Telecommunication'),
            ('computer', 'Electronic majoring in Computer'),
        ],
        'bs': [
            ('ai', 'Applied Artificial Intelligence'),
            ('ir', 'Intelligent Robotics'),
        ],
    },
    'fist': {
        'bcs': [
            ('ai', 'Artificial Intelligence'),
        ],
        'bit': [
            ('networking', 'Data Communications and Networking'),
            ('business', 'Business Intelligence and Analytics'),
            ('security', 'Security Technology'),
        ],
        'bs': [
            ('bioinfo', 'Bioinformatics'),
        ],
    },
    'fet': {
        'be': [
            ('telecomm', 'Electronic majoring in Telecommunication'),
        ],
    }
}

YEAR_CHOICES = [
    ('1', 'Year 1'),
    ('2', 'Year 2'),
    ('3', 'Year 3'),
    ('4', 'Year 4'),
]

EXPERTISE_CHOICES = [
    "Artificial Intelligence & Machine Learning",
    "Data Science & Analytics",
    "Cybersecurity & Digital Forensics",
    "Software & Application Development",
    "Algorithms & High Performance Computing",
    "Graphics, Games & Image Processing",
    "IoT & Embedded Systems",
    "Biotechnology & Bioinformatics",
    "Electronics & Electrical Engineering",
    "Mechanical & Manufacturing Engineering",
    "Physics & Photonics",
    "Sensors & Instrumentation",
    "Robotics & Control Systems",
    "Communication Systems & Wireless Technologies",
]

POSITION_CHOICES = [
    "Lecturer",
    "Senior Lecturer",
    "Assistant Professor",
    "Associate Professor",
    "Specialist 2",
]

MENTORSHIP_TYPE_CHOICES = [
    ('fyp', 'FYP / Final Year Project'),
    ('course', 'Course assistance'),
    ('personal', 'Personal project'),
    ('research', 'Research'),
    ('skill', 'Skill development'),
]

class StudentProfile(db.Model):
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id'),
        primary_key=True
    )

    full_name = db.Column(db.String(100), nullable=False)
    faculty = db.Column(db.String(10), nullable=False)      
    programme = db.Column(db.String(10), nullable=False)    
    year = db.Column(db.Integer, nullable=False)            
    specialization = db.Column(db.String(20), nullable=True)  
    bio = db.Column(db.Text)
    pfp = db.Column(db.String(255), nullable=True)

class MentorProfile(db.Model):
    user_id = db.Column(
        db.Integer, 
        db.ForeignKey('user.id'), 
        primary_key=True)

    full_name = db.Column(db.String(100), nullable=False)
    position = db.Column(db.String(10), nullable=False)          
    faculty = db.Column(db.String(10), nullable=False)           
    expertise = db.Column(db.String(150), nullable=False)         
    office_location = db.Column(db.String(50))
    linkedin_profile = db.Column(db.String(255))  
    pfp = db.Column(db.String(255), nullable=True)

class MentorshipRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    mentor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    mentorship_type = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(100), nullable=False) 
    description = db.Column(db.Text, nullable=False)           
    document_filename = db.Column(db.String(255), nullable=True)  

    status = db.Column(db.String(20), nullable=False, default='Pending')  
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    mentor_comment = db.Column(db.Text, nullable=True)
    responded_at = db.Column(db.DateTime, nullable=True)

    student = db.relationship('User', foreign_keys=[student_id], backref='sent_mentorship_requests')
    mentor = db.relationship('User', foreign_keys=[mentor_id], backref='received_mentorship_requests')

class Project(db.Model):
    """Project & Opportunities Board entries"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    skills_required = db.Column(db.String(200))
    project_type = db.Column(db.String(50))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    owner = db.relationship('User', backref='projects')


class ProjectMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User')
    project = db.relationship('Project', backref='members')


class ProjectMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # 🆕 parent message (null = top-level message)
    parent_id = db.Column(db.Integer, db.ForeignKey('project_message.id'), nullable=True)

    author = db.relationship('User')
    project = db.relationship('Project', backref='messages')

    # 🆕 self-relation: a message can have many replies
    replies = db.relationship(
        'ProjectMessage',
        backref=db.backref('parent', remote_side=[id]),
        lazy='dynamic'
    )


class Thread(db.Model):
    """Discussion threads"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    body = db.Column(db.Text, nullable=True)  
    category = db.Column(db.String(50))
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    score = db.Column(db.Integer, default=0)  
    creator = db.relationship('User', backref='threads')


class Post(db.Model):
    """Replies inside a thread"""
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    thread_id = db.Column(db.Integer, db.ForeignKey('thread.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # parent comment (for replies)
    parent_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=True)

    # relationships
    author = db.relationship('User', backref='posts')
    # self-referential relationship: one post can have many replies
    replies = db.relationship(
        'Post',
        backref=db.backref('parent', remote_side=[id]),
        lazy='dynamic'
    )


@login_manager.user_loader
def load_user(user_id):
    # Flask-Login uses this to reload the user from the session
    return User.query.get(int(user_id))


BASE_PROJECT_CATEGORIES = [
    "Competition",
    "Research",
    "Final Year Project",
    "Personal Project",
    "Event / Initiative",
]


BASE_THREAD_CATEGORIES = [
    "Find Team",
    "Ask for Help",
    "Share Resources",
    "General Discussion",
]


# ---------------------
# FORMS
# ---------------------
class RegisterForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Username"}
    )
    email = StringField(
        "Email",
        validators=[InputRequired(), Email(), Length(max=120)],
        render_kw={"placeholder": "Email"}
    )
    password = PasswordField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Password"}
    )
    role = RadioField(
        "Role",
        choices=[("student", "Student"), ("mentor", "Mentor")],
        default="student",
        validators=[InputRequired()]
    )
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("Username already exists. Please choose a different one.")

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError("Email already registered. Please use a different one.")


class LoginForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Username"}
    )
    password = PasswordField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Password"}
    )
    submit = SubmitField("Login")

class MentorshipRequestForm(FlaskForm):
    mentorship_type = SelectField(
        "Type of mentorship",
        choices=MENTORSHIP_TYPE_CHOICES,
        validators=[InputRequired()]
    )

    title = StringField(
        "Title",
        validators=[InputRequired(), Length(min=4, max=100)]
    )

    description = TextAreaField(
        "Describe what you need.",
        validators=[InputRequired(), Length(min=10)]
    )

    document = FileField(
        "Upload related document",
        validators=[
            FileAllowed(['pdf', 'doc', 'docx', 'zip', 'ppt', 'pptx'], 'Documents only!')
        ]
    )

    submit = SubmitField("Submit request")

class ProjectForm(FlaskForm):
    title = StringField(
        "Project / Opportunity Title",
        validators=[InputRequired(), Length(min=4, max=100)]
    )
    description = TextAreaField(
        "Description",
        validators=[InputRequired()]
    )
    skills_required = StringField(
        "Skills Required (optional)"
    )
    project_type = SelectField(
        "Category",
        choices=[
            ("Personal Project", "Personal Project"),
            ("Competition", "Competition"),
            ("Research", "Research"),
            ("Final Year Project", "Final Year Project"),
            ("Event / Initiative", "Event / Initiative"),
            ("Other", "Other"),
        ],
        default="Personal Project"
    )
    other_project_type = StringField(
        "Please specify (if Other)",
        render_kw={"placeholder": "e.g. Outreach, Admin Task"}
    )
    submit = SubmitField("Create")


class ProjectMessageForm(FlaskForm):
    content = TextAreaField(
        "Message",
        validators=[InputRequired()]
    )
    submit = SubmitField("Send")


class ThreadForm(FlaskForm):
    title = StringField(
        "Thread Title",
        validators=[InputRequired(), Length(min=4, max=150)]
    )
    body = TextAreaField(        
        "Content",
        validators=[InputRequired()]
    )
    category = SelectField(
        "Category",
        choices=[
            ("Find Team", "Find Team"),
            ("Ask for Help", "Ask for Help"),
            ("Share Resources", "Share Resources"),
            ("General Discussion", "General Discussion"),
            ("Other", "Other"),
        ],
        default="General Discussion"
    )
    other_category = StringField(
        "Please specify (if Other)",
        render_kw={"placeholder": "e.g. Career Talk, Admin Issues"}
    )
    submit = SubmitField("Create Thread")


class PostForm(FlaskForm):
    content = TextAreaField(
        "Reply",
        validators=[InputRequired()]
    )
    submit = SubmitField("Post Reply")


# ---------------------
# AUTH + PROFILE ROUTES
# ---------------------
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error_message = None

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                error_message = "Invalid password. Please try again."
        else:
            error_message = "Username does not exist. Please try again."

    return render_template('login.html', form=form, error_message=error_message)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_pw, role=form.role.data)

        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)

        # Then redirect to profile setup
        if new_user.role == 'student':
            return redirect(url_for('edit_student_profile'))
        else:
            return redirect(url_for('edit_mentor_profile'))

    return render_template('register.html', form=form)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/student/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_student_profile():
    if current_user.role != 'student':
        return redirect(url_for('home'))  

    profile = StudentProfile.query.filter_by(user_id=current_user.id).first()

    if request.method == 'POST':
        full_name = request.form.get('full_name')
        faculty = request.form.get('faculty')          
        programme = request.form.get('programme')      
        year = int(request.form.get('year'))          
        specialization = request.form.get('specialization') or None
        bio = request.form.get('bio')

        if not profile:
            profile = StudentProfile(user_id=current_user.id)

        #handle file upload
        file = request.files.get('pfp')
        if file and file.filename != '' and allowed_file(file.filename):
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = secure_filename(f"{current_user.id}.{ext}")  # e.g. 3.jpg
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            profile.pfp = filename

        profile.full_name = full_name
        profile.faculty = faculty
        profile.programme = programme
        profile.year = year
        profile.specialization = specialization
        profile.bio = bio

        db.session.add(profile)
        db.session.commit()

        return redirect(url_for('dashboard'))

    # GET: show form with existing values if profile exists
    return render_template(
        'edit_student.html',
        profile=profile,
        FACULTIES=FACULTIES,
        PROGRAMME_LABELS=PROGRAMME_LABELS,
        YEAR_CHOICES=YEAR_CHOICES,
        SPECIALIZATION_CHOICES=SPECIALIZATION_CHOICES,
    )

@app.route('/mentor/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_mentor_profile():
    if current_user.role != 'mentor':
        return redirect(url_for('home'))

    profile = MentorProfile.query.filter_by(user_id=current_user.id).first()

    if request.method == 'POST':
        full_name = request.form.get('full_name')
        position = request.form.get('position')
        faculty = request.form.get('faculty')
        office_location = request.form.get('office_location') or None
        linkedin_profile = request.form.get('linkedin_profile') or None
        expertise_list = request.form.getlist('expertise')

        # missing required fields
        if not (full_name and position and faculty and expertise_list):
            flash("Please fill in all required fields.", "error")
            return render_template(
                'edit_mentor.html',
                profile=profile,
                FACULTIES=FACULTIES,
                EXPERTISE_CHOICES=EXPERTISE_CHOICES,
                POSITION_CHOICES=POSITION_CHOICES,
            )

        # too many expertise selections
        if len(expertise_list) > 3:
            flash("You can select a maximum of 3 expertise areas.", "error")

            # keep what they already selected 
            if not profile:
                profile = MentorProfile(user_id=current_user.id)
            profile.full_name = full_name
            profile.position = position
            profile.faculty = faculty
            profile.office_location = office_location
            profile.linkedin_profile = linkedin_profile
            profile.expertise = ";".join(expertise_list)  

            return render_template(
                'edit_mentor.html',
                profile=profile,
                FACULTIES=FACULTIES,
                EXPERTISE_CHOICES=EXPERTISE_CHOICES,
                POSITION_CHOICES=POSITION_CHOICES,
            )

        if not profile:
            profile = MentorProfile(user_id=current_user.id)

        file = request.files.get('pfp')
        if file and file.filename != '' and allowed_file(file.filename):
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = secure_filename(f"{current_user.id}.{ext}")
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            profile.pfp = filename

        profile.full_name = full_name.strip()
        profile.position = position
        profile.faculty = faculty
        profile.expertise = ";".join(expertise_list)
        profile.office_location = office_location.strip() if office_location else None
        profile.linkedin_profile = linkedin_profile.strip() if linkedin_profile else None

        db.session.add(profile)
        db.session.commit()

        return redirect(url_for('dashboard'))

    return render_template(
        'edit_mentor.html',
        profile=profile,
        FACULTIES=FACULTIES,
        EXPERTISE_CHOICES=EXPERTISE_CHOICES,
        POSITION_CHOICES=POSITION_CHOICES,
    )


def get_programme_full_name(code):
    for fac, programmes in PROGRAMME_LABELS.items():
        for short, full in programmes:
            if short == code:
                return full
    return code  # fallback if not found

def get_spec_full_name(code):
    for fac, programmes in SPECIALIZATION_CHOICES.items():
        for prog_code, specs in programmes.items():
            for short, full in specs:
                if short == code:
                    return full
    return code  # fallback if not found

def get_faculty_full_name(code):
    for short, full in FACULTIES:
        if short == code:
            return full
    return code  # fallback if not found

def get_mentorship_type_label(code):
    for value, label in MENTORSHIP_TYPE_CHOICES:
        if value == code:
            return label
    return code

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'student':
        student_profile = current_user.student_profile
        programme_full = get_programme_full_name(student_profile.programme)
        specialization_full = None
        if student_profile.specialization:
            specialization_full = get_spec_full_name(student_profile.specialization)
        faculty_full = get_faculty_full_name(student_profile.faculty)

        owned_projects = Project.query.filter_by(owner_id=current_user.id)
        joined_project_ids = db.session.query(ProjectMember.project_id).filter_by(user_id=current_user.id)
        joined_projects = Project.query.filter(Project.id.in_(joined_project_ids))
        my_projects = owned_projects.union(joined_projects).order_by(Project.created_at.desc()).all()

        mentorship_requests = (MentorshipRequest.query
                        .filter_by(student_id=current_user.id)
                        .order_by(MentorshipRequest.created_at.desc())
                        .all())

        my_threads = Thread.query.filter_by(creator_id=current_user.id) \
                                    .order_by(Thread.created_at.desc()) \
                                    .all()

        return render_template(
            'dashboard_student.html',
            student_profile=student_profile,
            user=current_user,
            programme_full=programme_full,
            specialization_full=specialization_full,
            faculty_full=faculty_full,
            my_projects=my_projects,
            mentorship_requests=mentorship_requests,
            my_threads=my_threads,
            is_self=True
        )
    
    elif current_user.role == 'mentor':
        mentor_profile = current_user.mentor_profile
        position = mentor_profile.position if mentor_profile else None

        incoming_requests = (MentorshipRequest.query
                        .filter_by(mentor_id=current_user.id)
                        .order_by(MentorshipRequest.created_at.desc())
                        .all())
        
        accepted_mentees = (
            MentorshipRequest.query
                .filter_by(mentor_id=current_user.id, status='Accepted')
                .order_by(MentorshipRequest.created_at.desc())
                .all()
        )

        return render_template(
            'dashboard_mentor.html',
            mentor_profile=mentor_profile,
            user=current_user,
            position=position,
            incoming_requests=incoming_requests,
            accepted_mentees=accepted_mentees,
            get_mentorship_type_label=get_mentorship_type_label,
        )

@app.route('/users/<int:user_id>')
@login_required
def view_user(user_id):
    user = User.query.get_or_404(user_id)
    is_self = (user.id == current_user.id)

    student_projects = []
    student_threads = []

    if user.role == 'student':
        # use the viewed user's id, not current_user
        owned_projects = Project.query.filter_by(owner_id=user.id)

        joined_project_ids = db.session.query(ProjectMember.project_id) \
                                       .filter_by(user_id=user.id)
        joined_projects = Project.query.filter(Project.id.in_(joined_project_ids))

        student_projects = owned_projects.union(joined_projects) \
                                         .order_by(Project.created_at.desc()) \
                                         .all()

        student_threads = Thread.query.filter_by(creator_id=user.id) \
                                      .order_by(Thread.created_at.desc()) \
                                      .limit(5).all()

    return render_template(
        'profile_view.html',
        user=user,
        is_self=is_self,
        student_projects=student_projects,
        student_threads=student_threads,
        get_programme_full_name=get_programme_full_name,
        get_spec_full_name=get_spec_full_name,
        get_faculty_full_name=get_faculty_full_name,
    )


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ---------------------
# PROJECT & OPPORTUNITIES BOARD
# ---------------------
@app.route('/projects')
@login_required
def project_list():
    selected_category = request.args.get('category', 'All')

    query = Project.query
    if selected_category == 'All':
        pass
    elif selected_category == 'Other':
        query = query.filter(Project.project_type.notin_(BASE_PROJECT_CATEGORIES))
    else:
        query = query.filter_by(project_type=selected_category)

    projects = query.order_by(Project.created_at.desc()).all()
    return render_template(
        'projects.html',
        projects=projects,
        selected_category=selected_category
    )


@app.route('/projects/mine')
@login_required
def my_projects():
    selected_category = request.args.get('category', 'All')

    query = Project.query.filter_by(owner_id=current_user.id)
    if selected_category == 'All':
        pass
    elif selected_category == 'Other':
        query = query.filter(Project.project_type.notin_(BASE_PROJECT_CATEGORIES))
    else:
        query = query.filter_by(project_type=selected_category)

    projects = query.order_by(Project.created_at.desc()).all()
    return render_template(
        'projects.html',
        projects=projects,
        selected_category=selected_category,
        mine=True
    )

@app.route('/projects/create', methods=['GET', 'POST'])
@login_required
def create_project():
    form = ProjectForm()
    if form.validate_on_submit():
        if form.project_type.data == "Other":
            if not form.other_project_type.data or not form.other_project_type.data.strip():
                form.other_project_type.errors.append("Please specify the category.")
                return render_template('project_create.html', form=form)
            category_to_save = form.other_project_type.data.strip()
        else:
            category_to_save = form.project_type.data

        project = Project(
            title=form.title.data,
            description=form.description.data,
            skills_required=form.skills_required.data,
            project_type=category_to_save,
            owner_id=current_user.id
        )
        db.session.add(project)
        db.session.commit()
        return redirect(url_for('project_list'))

    return render_template('project_create.html', form=form)


@app.route('/projects/<int:project_id>')
@login_required
def project_detail(project_id):
    project = Project.query.get_or_404(project_id)

    membership = ProjectMember.query.filter_by(
        project_id=project.id,
        user_id=current_user.id
    ).first()

    member_count = ProjectMember.query.filter_by(project_id=project.id).count()
    members = ProjectMember.query.filter_by(project_id=project.id).all()

    return render_template(
        'project_detail.html',
        project=project,
        is_member=bool(membership),
        member_count=member_count,
        members=members
    )


@app.route('/projects/<int:project_id>/join')
@login_required
def join_project(project_id):
    project = Project.query.get_or_404(project_id)

    existing = ProjectMember.query.filter_by(
        project_id=project.id,
        user_id=current_user.id
    ).first()

    if not existing:
        membership = ProjectMember(project_id=project.id, user_id=current_user.id)
        db.session.add(membership)
        db.session.commit()

    # after joining, go straight to chat
    return redirect(url_for('project_chat', project_id=project.id))


@app.route('/projects/<int:project_id>/leave')
@login_required
def leave_project(project_id):
    membership = ProjectMember.query.filter_by(
        project_id=project_id,
        user_id=current_user.id
    ).first()

    if membership:
        db.session.delete(membership)
        db.session.commit()

    return redirect(url_for('project_detail', project_id=project_id))


@app.route('/projects/<int:project_id>/chat', methods=['GET', 'POST'])
@login_required
def project_chat(project_id):
    project = Project.query.get_or_404(project_id)

    # ensure user is member (auto-join if not)
    membership = ProjectMember.query.filter_by(
        project_id=project.id,
        user_id=current_user.id
    ).first()
    if not membership:
        membership = ProjectMember(project_id=project.id, user_id=current_user.id)
        db.session.add(membership)
        db.session.commit()

    form = ProjectMessageForm()
    if form.validate_on_submit():
        msg = ProjectMessage(
            project_id=project.id,
            author_id=current_user.id,
            content=form.content.data,
            parent_id=None   # 🔹 top-level message
        )
        db.session.add(msg)
        db.session.commit()
        return redirect(url_for('project_chat', project_id=project.id))

    messages = ProjectMessage.query.filter_by(project_id=project.id) \
                                   .order_by(ProjectMessage.created_at.asc()).all()
    members = ProjectMember.query.filter_by(project_id=project.id).all()

    return render_template(
        'project_chat.html',
        project=project,
        form=form,
        messages=messages,
        members=members
    )


@app.route('/projects/<int:project_id>/chat/reply/<int:parent_id>', methods=['GET', 'POST'])
@login_required
def reply_project_message(project_id, parent_id):
    project = Project.query.get_or_404(project_id)
    parent_message = ProjectMessage.query.get_or_404(parent_id)

    # safety: ensure parent message belongs to this project
    if parent_message.project_id != project.id:
        return redirect(url_for('project_chat', project_id=project.id))

    form = ProjectMessageForm()
    if form.validate_on_submit():
        reply = ProjectMessage(
            project_id=project.id,
            author_id=current_user.id,
            content=form.content.data,
            parent_id=parent_message.id   # 🔹 link to parent
        )
        db.session.add(reply)
        db.session.commit()
        return redirect(url_for('project_chat', project_id=project.id))

    members = ProjectMember.query.filter_by(project_id=project.id).all()

    return render_template(
        'reply_project_message.html',
        project=project,
        parent_message=parent_message,
        form=form,
        members=members
    )


# ---------------------
# BASIC DISCUSSION BOARD
# ---------------------
@app.route('/forum')
@login_required
def forum():
    selected_category = request.args.get('category', 'All')
    sort = request.args.get('sort', 'new') 

    query = Thread.query

    if selected_category == 'All':
        pass
    elif selected_category == 'Other':
        query = query.filter(Thread.category.notin_(BASE_THREAD_CATEGORIES))
    else:
        query = query.filter_by(category=selected_category)

    # sorting
    if sort == 'top':
        query = query.order_by(Thread.score.desc(), Thread.created_at.desc())
    else:  # 'new'
        query = query.order_by(Thread.created_at.desc())

    threads = query.all()

    return render_template(
        'forum.html',
        threads=threads,
        selected_category=selected_category,
        sort=sort,
        mine=False
    )


@app.route('/forum/mine')
@login_required
def my_threads():
    selected_category = request.args.get('category', 'All')

    query = Thread.query.filter_by(creator_id=current_user.id)
    if selected_category == 'All':
        pass
    elif selected_category == 'Other':
        query = query.filter(Thread.category.notin_(BASE_THREAD_CATEGORIES))
    else:
        query = query.filter_by(category=selected_category)

    threads = query.order_by(Thread.created_at.desc()).all()
    return render_template(
        'forum.html',
        threads=threads,
        selected_category=selected_category,
        mine=True 
    )


@app.route('/forum/create', methods=['GET', 'POST'])
@login_required
def create_thread():
    form = ThreadForm()
    if form.validate_on_submit():
        # category handling
        if form.category.data == "Other":
            if not form.other_category.data or not form.other_category.data.strip():
                form.other_category.errors.append("Please specify the category.")
                return render_template('thread_create.html', form=form)
            category_to_save = form.other_category.data.strip()
        else:
            category_to_save = form.category.data

        thread = Thread(
            title=form.title.data,
            body=form.body.data,          
            category=category_to_save,
            creator_id=current_user.id
        )
        db.session.add(thread)
        db.session.commit()
        return redirect(url_for('forum'))

    return render_template('thread_create.html', form=form)


@app.route('/forum/<int:thread_id>', methods=['GET', 'POST'])
@login_required
def thread_detail(thread_id):
    thread = Thread.query.get_or_404(thread_id)
    form = PostForm()

    # this form is for **top-level** comments (not replies)
    if form.validate_on_submit():
        post = Post(
            content=form.content.data,
            thread_id=thread.id,
            author_id=current_user.id,
            parent_id=None   # top-level
        )
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('thread_detail', thread_id=thread.id))

    posts = Post.query.filter_by(thread_id=thread.id).order_by(Post.created_at.asc()).all()
    return render_template('thread_detail.html', thread=thread, posts=posts, form=form)


@app.route('/forum/<int:thread_id>/reply/<int:parent_id>', methods=['GET', 'POST'])
@login_required
def reply_post(thread_id, parent_id):
    thread = Thread.query.get_or_404(thread_id)
    parent_post = Post.query.get_or_404(parent_id)

    # make sure the parent post belongs to this thread
    if parent_post.thread_id != thread.id:
        return redirect(url_for('thread_detail', thread_id=thread.id))

    form = PostForm()
    if form.validate_on_submit():
        reply = Post(
            content=form.content.data,
            thread_id=thread.id,
            author_id=current_user.id,
            parent_id=parent_post.id  # 🆕 link to parent
        )
        db.session.add(reply)
        db.session.commit()
        return redirect(url_for('thread_detail', thread_id=thread.id))

    # we’ll show a small reply page with parent comment context
    return render_template('reply_post.html', thread=thread, parent_post=parent_post, form=form)


@app.route('/forum/<int:thread_id>/upvote')
@login_required
def upvote_thread(thread_id):
    thread = Thread.query.get_or_404(thread_id)
    thread.score = (thread.score or 0) + 1
    db.session.commit()
    return redirect(url_for('thread_detail', thread_id=thread.id))


@app.route('/forum/<int:thread_id>/downvote')
@login_required
def downvote_thread(thread_id):
    thread = Thread.query.get_or_404(thread_id)
    thread.score = (thread.score or 0) - 1
    db.session.commit()
    return redirect(url_for('thread_detail', thread_id=thread.id))

# ---------------------
# DIRECTORY
# ---------------------
@app.route('/directory')
@login_required
def directory():
    q = request.args.get('q', '').strip()
    role_filter = request.args.get('role', 'all')  #

    faculty_filter = request.args.getlist('faculty')     
    expertise_filter = request.args.getlist('expertise')  

    combined_list = []

    # ---------- STUDENTS ----------
    if role_filter in ('all', 'student'):
        student_query = StudentProfile.query.join(User, StudentProfile.user_id == User.id)
        student_query = student_query.filter(User.id != current_user.id)

        if q:
            student_query = student_query.filter(StudentProfile.full_name.ilike(f"%{q}%"))

        # only filter by faculty if at least one was selected
        if faculty_filter:
            student_query = student_query.filter(StudentProfile.faculty.in_(faculty_filter))

        students = [
            {
                "type": "student",
                "id": s.user_id,
                "name": s.full_name,
                "faculty": s.faculty,
                "programme": s.programme,
                "specialization": s.specialization,
                "year": s.year,
                "pfp": s.pfp,
            }
            for s in student_query.all()
        ]

        combined_list.extend(students)

    # ---------- MENTORS ----------
    if role_filter in ('all', 'mentor'):
        mentor_query = MentorProfile.query.join(User, MentorProfile.user_id == User.id)
        mentor_query = mentor_query.filter(User.id != current_user.id)

        if q:
            mentor_query = mentor_query.filter(MentorProfile.full_name.ilike(f"%{q}%"))

        if faculty_filter:
            mentor_query = mentor_query.filter(MentorProfile.faculty.in_(faculty_filter))

        if expertise_filter:
            conditions = [
                MentorProfile.expertise.ilike(f"%{e}%")
                for e in expertise_filter
            ]
            mentor_query = mentor_query.filter(or_(*conditions))

        mentors = [
            {
                "type": "mentor",
                "id": m.user_id,
                "name": m.full_name,
                "faculty": m.faculty,
                "position": m.position,
                "expertise": m.expertise,
                "pfp": m.pfp,
            }
            for m in mentor_query.all()
        ]

        combined_list.extend(mentors)

    combined_list.sort(key=lambda x: x["name"].lower())

    return render_template(
        "directory.html",
        combined_list=combined_list,
        get_programme_full_name=get_programme_full_name,
        get_spec_full_name=get_spec_full_name,
        FACULTIES=FACULTIES,
        EXPERTISE_CHOICES=EXPERTISE_CHOICES,
        search_query=q,
        role_filter=role_filter,
        faculty_filter=faculty_filter,       
        expertise_filter=expertise_filter,   
    )

# ---------------------
# MENTORSHIP REQUESTS
# ---------------------
@app.route('/request_mentorship/<int:mentor_id>', methods=['GET', 'POST'])
@login_required
def request_mentorship(mentor_id):
    # only students can send mentorship requests
    if current_user.role != 'student':
        flash("Only students can request mentorship.", "error")
        return redirect(url_for('dashboard'))

    # get the mentor user
    mentor = User.query.get_or_404(mentor_id)

    # make sure the target is actually a mentor
    if mentor.role != 'mentor':
        flash("You can only request mentorship from mentor accounts.", "error")
        return redirect(url_for('directory'))

    form = MentorshipRequestForm()

    if form.validate_on_submit():
        filename = None

        if form.document.data:
            file = form.document.data
            if file.filename:  
                safe_name = secure_filename(file.filename)
                os.makedirs(app.config['MENTORSHIP_DOCUMENTS'], exist_ok=True)
                upload_path = os.path.join(app.config['MENTORSHIP_DOCUMENTS'], safe_name)
                file.save(upload_path)
                filename = safe_name

        new_req = MentorshipRequest(
            student_id=current_user.id,
            mentor_id=mentor.id,  
            mentorship_type=form.mentorship_type.data,
            title=form.title.data.strip(),
            description=form.description.data.strip(),
            document_filename=filename  
        )

        db.session.add(new_req)
        db.session.commit()

        flash("Your mentorship request has been sent.", "request_sent")
        return redirect(url_for('view_user', user_id=mentor.id))

    return render_template(
        'request_mentorship.html',
        form=form,
        mentor=mentor 
    )

@app.route('/mentorship_requests/<int:req_id>', methods=['GET', 'POST'])
@login_required
def review_mentor_request(req_id):
    req = MentorshipRequest.query.get_or_404(req_id)

    # only the student or the mentor involved can see it
    if current_user.id not in (req.student_id, req.mentor_id):
        abort(403)

    is_mentor = (current_user.id == req.mentor_id)
    is_student = (current_user.id == req.student_id)

    # Mentor can accept / decline with a comment
    if is_mentor and request.method == 'POST':
        action = request.form.get('action')
        comment = request.form.get('mentor_comment', '').strip() 

        if action == 'accept':
            req.status = 'Accepted'
        elif action == 'decline':
            req.status = 'Declined'
        else:
            flash("Invalid action.", "error")
            return redirect(url_for('review_mentor_request', req_id=req.id))

        req.mentor_comment = comment
        req.responded_at = datetime.utcnow()
        db.session.commit()

        flash(f"You have {req.status.lower()} this request.", "mentor_response")
        return redirect(url_for('review_mentor_request', req_id=req.id))

    return render_template(
        'review_mentor_request.html',
        req=req,
        is_mentor=is_mentor,
        is_student=is_student,
        mentor_type=get_mentorship_type_label(req.mentorship_type)
    )

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, RadioField, TextAreaField, SelectField
from wtforms.validators import InputRequired, Length, ValidationError, Email
from flask_bcrypt import Bcrypt
from datetime import datetime
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'TripleABattery'
app.config['UPLOAD_FOLDER'] = 'static/assets/pfp'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

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
                return redirect(url_for('profile'))
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

        return redirect(url_for('profile'))

    # GET: show form with existing values if profile exists
    return render_template(
        'student_profile_form.html',
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
        expertise = request.form.get('expertise')
        office_location = request.form.get('office_location') or None
        linkedin_profile = request.form.get('linkedin_profile') or None

        if not (full_name and position and faculty and expertise):
            error = "Please fill in all required fields."
            return render_template(
                'mentor_profile_form.html',
                profile=profile,
                FACULTIES=FACULTIES,
                EXPERTISE_CHOICES=EXPERTISE_CHOICES,
                POSITION_CHOICES=POSITION_CHOICES,
                error=error,
            )

        if not profile:
            profile = MentorProfile(user_id=current_user.id)

        #handle file upload
        file = request.files.get('pfp')
        if file and file.filename != '' and allowed_file(file.filename):
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = secure_filename(f"{current_user.id}.{ext}")  # e.g. 5.png
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            profile.pfp = filename

        profile.full_name = full_name.strip()
        profile.position = position
        profile.faculty = faculty
        profile.expertise = expertise
        profile.office_location = office_location.strip() if office_location else None
        profile.linkedin_profile = linkedin_profile.strip() if linkedin_profile else None

        db.session.add(profile)
        db.session.commit()

        return redirect(url_for('profile'))  

    # GET: show form with existing values if profile exists
    return render_template(
        'mentor_profile_form.html',
        profile=profile,
        FACULTIES=FACULTIES,
        EXPERTISE_CHOICES=EXPERTISE_CHOICES,
        POSITION_CHOICES=POSITION_CHOICES,
    )

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user, is_self=True)


@app.route('/users/<int:user_id>')
@login_required
def view_user(user_id):
    user = User.query.get_or_404(user_id)
    is_self = (user.id == current_user.id)
    return render_template('profile.html', user=user, is_self=is_self)


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


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

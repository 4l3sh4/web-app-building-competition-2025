from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, RadioField, TextAreaField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from datetime import datetime

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'TripleABattery'

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
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'student' or 'mentor'

    # one-to-one relationships
    student_profile = db.relationship('StudentProfile', backref='user', uselist=False)
    mentor_profile = db.relationship('MentorProfile', backref='user', uselist=False)

FACULTIES = [
    ('fci', 'Faculty of Computing & Informatics (FCI)'),
    ('faie', 'Faculty of Artificial Intelligence & Engineering (FAIE)')
]

PROGRAMME_LABELS = {
    'fci': [
        ('bcs', 'Bachelor of Computer Science (Hons.)'),
        ('bit', 'Bachelor of Information Technology (Hons.) (Information Systems)'),
        ('dit', 'Diploma in Information Technology'),
    ],

    'faie': [
        ('be', 'Bachelor of Engineering (Hons.)'),
        ('bs', 'Bachelor of Science (Hons.)'),
    ]
}

SPECIALIZATION_CHOICES = {
    'bcs': [
        ('cyber', 'Cybersecurity'),
        ('se', 'Software Engineering'),
        ('ds', 'Data Science'),
        ('game', 'Game Development'),
    ],
    'be': [
        ('electrical', 'Electrical'),
        ('electronics', 'Electronics'),
        ('et', 'Electronic majoring in Telecommunication'),
        ('ec', 'Electronic majoring in Computer'),
    ],
    'bs': [
        ('ai', 'Applied Artificial Intelligence'),
        ('ir', 'Intelligent Robotics'),
    ],
}

YEAR_CHOICES = [
    ('1', 'Year 1'),
    ('2', 'Year 2'),
    ('3', 'Year 3'),
    ('4', 'Year 4'),
]

class StudentProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id'),
        nullable=False,
        unique=True
    )

    full_name = db.Column(db.String(100), nullable=False)

    faculty = db.Column(db.String(10), nullable=False)      # 'fci', 'faie'
    programme = db.Column(db.String(10), nullable=False)    # 'bcs', 'bit', 'dit', 'be', 'bs'
    year = db.Column(db.Integer, nullable=False)            

    specialization = db.Column(db.String(20), nullable=True)  

    interests = db.Column(db.Text)      
    skills = db.Column(db.Text)
    bio = db.Column(db.Text)


class MentorProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)

    full_name = db.Column(db.String(100), nullable=False)
    position = db.Column(db.String(100))         
    department = db.Column(db.String(100))

    expertise = db.Column(db.Text)               
    research_interests = db.Column(db.Text)
    office_location = db.Column(db.String(100))
    contact_method = db.Column(db.String(150))   # email or link
    max_mentees = db.Column(db.Integer)

class Project(db.Model):
    """Project & Opportunities Board entries"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    skills_required = db.Column(db.String(200))
    project_type = db.Column(db.String(50))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Thread(db.Model):
    """Discussion threads"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(50))
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Post(db.Model):
    """Replies inside a thread"""
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    thread_id = db.Column(db.Integer, db.ForeignKey('thread.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    # Flask-Login uses this to reload the user from the session
    return User.query.get(int(user_id))


# ---------------------
# FORMS
# ---------------------
class RegisterForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Username"}
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
    project_type = StringField(
        "Type (e.g. competition, research, personal)",
        render_kw={"placeholder": "competition / research / personal"}
    )
    submit = SubmitField("Create")


class ThreadForm(FlaskForm):
    title = StringField(
        "Thread Title",
        validators=[InputRequired(), Length(min=4, max=150)]
    )
    category = StringField(
        "Category (optional)",
        render_kw={"placeholder": "Find Team / Ask Mentor / Resources"}
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
        new_user = User(username=form.username.data, password=hashed_pw, role=form.role.data)

        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)

        # Then redirect to profile setup
        if new_user.role == 'student':
            return redirect(url_for('setup_student_profile'))
        else:
            return redirect(url_for('setup_mentor_profile'))

    return render_template('register.html', form=form)

@app.route('/student/profile/setup', methods=['GET', 'POST'])
@login_required
def setup_student_profile():
    if current_user.role != 'student':
        return redirect(url_for('home'))  # you don't have 'index', so use 'home'

    profile = StudentProfile.query.filter_by(user_id=current_user.id).first()

    if request.method == 'POST':
        full_name = request.form.get('full_name')
        faculty = request.form.get('faculty')          # 'fci' / 'faie'
        programme = request.form.get('programme')      # 'bcs' / 'bit' / ...
        year = int(request.form.get('year'))           # '1' -> 1
        specialization = request.form.get('specialization') or None
        interests = request.form.get('interests')
        skills = request.form.get('skills')
        bio = request.form.get('bio')

        if not profile:
            profile = StudentProfile(user_id=current_user.id)

        profile.full_name = full_name
        profile.faculty = faculty
        profile.programme = programme
        profile.year = year
        profile.specialization = specialization
        profile.interests = interests
        profile.skills = skills
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

@app.route('/profile')
@login_required
def profile():
    # shows username + role in profile.html
    return render_template('profile.html', user=current_user)


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
    projects = Project.query.order_by(Project.created_at.desc()).all()
    return render_template('projects.html', projects=projects)


@app.route('/projects/create', methods=['GET', 'POST'])
@login_required
def create_project():
    form = ProjectForm()
    if form.validate_on_submit():
        project = Project(
            title=form.title.data,
            description=form.description.data,
            skills_required=form.skills_required.data,
            project_type=form.project_type.data,
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
    # If you want owner username, you could look it up here later
    return render_template('project_detail.html', project=project)


# ---------------------
# BASIC DISCUSSION BOARD
# ---------------------
@app.route('/forum')
@login_required
def forum():
    threads = Thread.query.order_by(Thread.created_at.desc()).all()
    return render_template('forum.html', threads=threads)


@app.route('/forum/create', methods=['GET', 'POST'])
@login_required
def create_thread():
    form = ThreadForm()
    if form.validate_on_submit():
        thread = Thread(
            title=form.title.data,
            category=form.category.data,
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
    if form.validate_on_submit():
        post = Post(
            content=form.content.data,
            thread_id=thread.id,
            author_id=current_user.id
        )
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('thread_detail', thread_id=thread.id))

    posts = Post.query.filter_by(thread_id=thread.id).order_by(Post.created_at.asc()).all()
    return render_template('thread_detail.html', thread=thread, posts=posts, form=form)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

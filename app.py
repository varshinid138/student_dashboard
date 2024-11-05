import json  # Import the standard json module
from flask import Flask, render_template, redirect, request, url_for, flash
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_required, login_user, current_user, logout_user
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField
from wtforms.validators import InputRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import boto3 

# Database setup
dbdir = "sqlite:///" + os.path.abspath(os.getcwd()) + "/database2.db"


app = Flask(__name__)
app.config["SECRET_KEY"] = "SomeSecret"
app.config["SQLALCHEMY_DATABASE_URI"] = dbdir
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# E2E Object Storage configuration
E2E_ACCESS_KEY = 'ZCQ4MWQWOVRS5V4WDBWZ'
E2E_SECRET_KEY = 'PR78IAP2FXMQ9JLF5XSNXXU7OYOVXTYK7X1G4VLM'
E2E_BUCKET_NAME = 'project'
E2E_REGION = 'us-east-1'
E2E_ENDPOINT_URL = 'https://objectstore.e2enetworks.net'

# Set up boto3 client for E2E object storage
s3_client = boto3.client(
    's3',
    aws_access_key_id=E2E_ACCESS_KEY,
    aws_secret_access_key=E2E_SECRET_KEY,
    endpoint_url=E2E_ENDPOINT_URL,
    region_name=E2E_REGION
)

# User model
class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    usertype = db.Column(db.String(50), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

# Forms
class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=5, max=50)])
    email = StringField("Email", validators=[InputRequired(), Length(min=5, max=50)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=6, max=80)])
    usertype = SelectField("User Type", 
                           choices=[ 
                                    ('admin', 'Admin'), 
                                    ('user', 'User')],
                           validators=[InputRequired()])
    submit = SubmitField("Sign Up")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=5, max=50)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=6, max=80)])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Log In")


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember)
            username = user.username
            if user.usertype == "admin":
                return render_template("admin.html", username=username)
            else:
                return redirect(url_for("user_dashboard"))
        return "Your credentials are invalid."
    return render_template("login.html", form=form)

@app.route("/user_signup", methods=["GET", "POST"])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        new_user = Users(username=form.username.data, email=form.email.data, password=hashed_pw, usertype=form.usertype.data)
        db.session.add(new_user)
        db.session.commit()
        flash("You've been registered successfully, now you can log in.")
        return redirect(url_for("login"))
    return render_template("signup.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You were logged out. See you soon!")
    return redirect(url_for("index"))

@app.route("/admin/users")
@login_required
def admin_users():
    if current_user.usertype != 'admin':
        flash("You do not have permission to view this page.")
        return redirect(url_for('index'))

    # Retrieve only users with usertype='user'
    users = Users.query.filter_by(usertype='user').all()
    user_assignments = {}

    # Load existing assignments from the JSON file
    if os.path.exists('user_assignments.json'):
        with open('user_assignments.json', 'r') as json_file:
            try:
                user_assignments = json.load(json_file)
                user_assignments = {int(k): v for k, v in user_assignments.items()}
            except json.JSONDecodeError:
                user_assignments = {}

    # Merge user assignments with user data
    for user in users:
        user_id = user.id
        if user_id in user_assignments:
            user.assigned_projects = user_assignments[user_id].get("assigned_projects", [])
        else:
            user.assigned_projects = []

    return render_template("admin_users.html", users=users)

    
@app.route("/admin/assign_project/<int:user_id>", methods=["GET", "POST"])
@login_required
def assign_project(user_id):
    if current_user.usertype != 'admin':
        flash("You do not have permission to view this page.")
        return redirect(url_for('index'))

    # Fetch project names and links directly from the E2E bucket
    projects = []
    try:
        response = s3_client.list_objects_v2(Bucket=E2E_BUCKET_NAME)
        if 'Contents' in response:
            for obj in response['Contents']:
                project_name = obj['Key']
                project_link = f"{E2E_ENDPOINT_URL}/{E2E_BUCKET_NAME}/{project_name}"
                projects.append({
                    "project_name": project_name,
                    "project_link": project_link
                })
        else:
            flash("No projects found in the E2E bucket.", "warning")
    except Exception as e:
        flash(f"Failed to retrieve projects from E2E bucket: {str(e)}", "danger")

    if request.method == "POST":
        selected_projects = request.form.getlist('projects')

        # Load existing assignments or create new ones
        user_assignments = {}
        if os.path.exists('user_assignments.json'):
            with open('user_assignments.json', 'r') as json_file:
                try:
                    user_assignments = json.load(json_file)
                    user_assignments = {int(k): v for k, v in user_assignments.items()}
                except json.JSONDecodeError:
                    user_assignments = {}

        # Assign the selected projects to the user
        user_assignments[user_id] = {
            "username": Users.query.get(user_id).username,
            "assigned_projects": []
        }

        # For each selected project, store its name and link
        for project_name in selected_projects:
            project_link = next((p["project_link"] for p in projects if p["project_name"] == project_name), None)
            if project_link:
                user_assignments[user_id]["assigned_projects"].append({
                    "project_name": project_name,
                    "project_link": project_link
                })

        # Save the updated assignments back to user_assignments.json
        with open('user_assignments.json', 'w') as json_file:
            json.dump(user_assignments, json_file, indent=4)

        flash("Projects assigned successfully!")
        return redirect(url_for("admin_users"))

    return render_template("assign_project.html", projects=projects, user_id=user_id)

@app.route("/admin/create_project", methods=["GET", "POST"])
@login_required
def create_project():
    if current_user.usertype != 'admin':
        flash("You do not have permission to view this page.")
        return redirect(url_for('index'))

    if request.method == "POST":
        project_name = request.form.get("project_name")
        project_file = request.files.get("project_file")

        if project_file:
            # Check if the file is a valid type
            if project_file.filename.endswith(('.txt', '.docx')):
                # Create a unique file name if necessary
                s3_file_key = f"projects/{project_name}.{project_file.filename.split('.')[-1]}"

                # Upload project file to S3
                try:
                    s3_client.upload_fileobj(
                        project_file,
                        E2E_BUCKET_NAME,
                        s3_file_key,
                        ExtraArgs={'ContentType': project_file.content_type}
                    )
                    flash("Project file uploaded successfully!")
                except Exception as e:
                    flash(f"Failed to upload project file to e2e bucket: {e}", "danger")
                    return redirect(url_for("admin_users"))
            else:
                flash("Invalid file type. Please upload a .txt or .docx file.", "danger")
                return redirect(url_for("create_project"))
        else:
            flash("No file uploaded. Please select a file to upload.", "danger")
            return redirect(url_for("create_project"))

        return redirect(url_for("admin_users"))

    return render_template("create_project.html")



@app.route("/user/dashboard")
@login_required
def user_dashboard():
    if current_user.usertype != 'user':
        flash("You do not have permission to view this page.")
        return redirect(url_for('index'))

    # Load existing assignments
    user_assignments = {}
    if os.path.exists('user_assignments.json'):
        with open('user_assignments.json', 'r') as json_file:
            try:
                user_assignments = json.load(json_file)
                # Convert keys to integers
                user_assignments = {int(k): v for k, v in user_assignments.items()}
            except json.JSONDecodeError:
                user_assignments = {}

    # Get the current user's assigned projects
    assigned_projects = user_assignments.get(current_user.id, {}).get("assigned_projects", [])

    return render_template("user_dashboard.html", assigned_projects=assigned_projects)



UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/upload/<project_name>', methods=['POST'])
@login_required
def upload_file_or_folder(project_name):
    # Sanitize project name to avoid invalid folder names
    safe_project_name = secure_filename(project_name)

    if 'upload' not in request.files:
        flash('No file or folder selected for uploading')
        return redirect(url_for('user_dashboard'))

    files = request.files.getlist('upload')
    upload_success = False

    # Define base path for user's project folder within central uploads directory
    user_upload_folder = os.path.join(UPLOAD_FOLDER, f"user_{current_user.id}", safe_project_name)
    os.makedirs(user_upload_folder, exist_ok=True)

    for file in files:
        if file:  # Check if the file exists in the request
            # Preserve folder structure of the uploaded files
            relative_path = secure_filename(file.filename)
            save_path = os.path.join(user_upload_folder, relative_path)
            os.makedirs(os.path.dirname(save_path), exist_ok=True)  # Create subdirectories as needed

            try:
                file.save(save_path)
                upload_success = True
            except Exception as e:
                flash(f"Failed to upload '{file.filename}': {str(e)}")

    if upload_success:
        flash("Files or folders uploaded successfully!")
    else:
        flash("No files were uploaded.")

    return redirect(url_for('user_dashboard'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # Run on all available interfaces (0.0.0.0) on port 5000
        app.run(host='0.0.0.0', port=5000)

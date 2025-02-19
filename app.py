from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import re
import os
from werkzeug.utils import secure_filename
from flask import send_from_directory

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///job_portal.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)
    applications = db.relationship('Application', backref='user', lazy=True)

class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    company = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    employer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    applications = db.relationship('Application', backref='job', lazy=True, cascade="all, delete-orphan")

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    resume = db.Column(db.Text, nullable=False)
    cover_letter = db.Column(db.Text, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
   
    return render_template('index.html')

@app.route('/rojgarhub')
def rojgarhub():
    return redirect(url_for('index'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password')
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user_type = request.form['user_type']
        
        # Password validation
        if len(password) < 8 or not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            flash('Password must be at least 8 characters long and contain at least one special character.')
            return render_template('signup.html')
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists')
        else:
            new_user = User(email=email, password=generate_password_hash(password), user_type=user_type)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully. Please log in.')
            return redirect(url_for('login'))
    return render_template('signup.html')


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.user_type == 'jobseeker':
        jobs = Job.query.all()
        applications = Application.query.filter_by(user_id=current_user.id).all()
        return render_template('jobseeker_dashboard.html', jobs=jobs, applications=applications)
    elif current_user.user_type == 'employer':
        jobs = Job.query.filter_by(employer_id=current_user.id).all()
        return render_template('employer_dashboard.html', jobs=jobs)

@app.route('/post_job', methods=['POST'])
@login_required
def post_job():
    if current_user.user_type == 'employer':
        title = request.form['title']
        company = request.form['company']
        description = request.form['description']
        location = request.form['location']
        new_job = Job(title=title, company=company, description=description, location=location, employer_id=current_user.id)
        db.session.add(new_job)
        db.session.commit()
        flash('Job posted successfully')
    return redirect(url_for('dashboard'))

@app.route('/apply_job/<int:job_id>', methods=['POST'])
@login_required
def apply_job(job_id):
    if current_user.user_type == 'jobseeker':
        resume = request.files['resume']
        cover_letter = request.form['cover_letter']
        
        if 'UPLOAD_FOLDER' in app.config:
            resume_filename = secure_filename(resume.filename)
            resume_path = os.path.join(app.config['UPLOAD_FOLDER'], resume_filename)
            resume.save(resume_path)
            
            new_application = Application(
                job_id=job_id,
                user_id=current_user.id,
                resume=resume_filename,
                cover_letter=cover_letter
            )
            db.session.add(new_application)
            db.session.commit()
            return jsonify(success=True)
        else:
            flash('Error: Upload folder is not configured correctly.')
            return jsonify(success=False)
    return jsonify(success=False)

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if request.method == 'POST':
        # Process the submitted feedback
        # You can save it to the database or send an email
        flash('Thank you for your feedback!', 'success')
        return redirect(url_for('index'))
    return render_template('feedback.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/delete_job/<int:job_id>', methods=['POST'])
@login_required
def delete_job(job_id):
    job = Job.query.get_or_404(job_id)
    if job.employer_id == current_user.id:
        db.session.delete(job)
        db.session.commit()
        flash('Job deleted successfully')
    else:
        flash('You are not authorized to delete this job')
    return redirect(url_for('dashboard'))


@app.route('/application_details/<int:application_id>', methods=['GET'])
@login_required
def application_details(application_id):
    application = Application.query.get_or_404(application_id)
    if application.user_id == current_user.id:
        return jsonify(
            job_title=application.job.title,
            company=application.job.company,
            location=application.job.location,
            description=application.job.description,
            resume=application.resume,
            cover_letter=application.cover_letter
        )
    return jsonify(success=False), 403


@app.route('/job_details/<int:job_id>', methods=['GET'])
@login_required
def job_details(job_id):
    job = Job.query.get_or_404(job_id)
    return jsonify(
        title=job.title,
        company=job.company,
        location=job.location,
        description=job.description
    )

@app.route('/edit_application/<int:application_id>', methods=['POST'])
@login_required
def edit_application(application_id):
    application = Application.query.get_or_404(application_id)
    if application.user_id != current_user.id:
        return jsonify(success=False), 403

    cover_letter = request.form['cover_letter']
    resume = request.files.get('resume')

    if resume:
        resume_filename = secure_filename(resume.filename)
        resume.save(os.path.join(app.config['UPLOAD_FOLDER'], resume_filename))
        application.resume = resume_filename

    application.cover_letter = cover_letter
    db.session.commit()
    return jsonify(success=True)

@app.route('/delete_application/<int:application_id>', methods=['POST'])
@login_required
def delete_application(application_id):
    application = Application.query.get_or_404(application_id)
    if application.user_id != current_user.id:
        return jsonify(success=False), 403

    db.session.delete(application)
    db.session.commit()
    return jsonify(success=True)

@app.route('/employer_application_details/<int:application_id>', methods=['GET'])
@login_required
def employer_application_details(application_id):
    application = Application.query.get_or_404(application_id)
    job = Job.query.get_or_404(application.job_id)
    if job.employer_id != current_user.id:
        return jsonify(success=False), 403

    return jsonify(
        job_title=application.job.title,
        company=application.job.company,
        location=application.job.location,
        description=application.job.description,
        resume=application.resume,
        cover_letter=application.cover_letter,
        applicant_email=application.user.email
    )

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
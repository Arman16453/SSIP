from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_migrate import Migrate
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import extract
import os
import json
import time
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import openai
from flask_wtf.csrf import CSRFProtect

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ssip.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your-email@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your-app-password')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME', 'your-email@gmail.com')
app.config['UPLOAD_FOLDER'] = 'uploads'

# Initialize serializer for secure tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Initialize CSRF protection
csrf = CSRFProtect(app)

CHATBOT_RESPONSES = {
    'default': 'I can help you with information about SSIP (Student Startup and Innovation Policy). SSIP is a Gujarat government initiative to support innovative student projects. Ask me about what SSIP is, how to apply, or about funding!',
    
    'what': {
        'keywords': ['what', 'ssip', 'about', 'tell me', 'explain'],
        'response': 'SSIP (Student Startup and Innovation Policy) is a Gujarat government initiative that:\n1. Supports innovative student projects\n2. Provides funding up to ₹2,00,000\n3. Helps develop entrepreneurship skills\n4. Encourages technology-based solutions\n5. Connects students with mentors'
    },
    
    'application': {
        'keywords': ['submit', 'application', 'apply', 'how to apply', 'new application'],
        'response': 'To submit a new application: 1. Log in to your account, 2. Click "Submit New Application" on your dashboard, 3. Fill in project details, 4. Upload required documents, 5. Submit for review.'
    },
    
    'funding': {
        'keywords': ['fund', 'money', 'amount', 'grant', 'financial'],
        'response': 'SSIP provides funding up to ₹2,00,000 for approved projects. The amount depends on your project requirements and the evaluation by the review committee.'
    },
    
    'documents': {
        'keywords': ['document', 'file', 'upload', 'requirement', 'quotation'],
        'response': 'Required documents: 1. Project proposal, 2. Cost estimates/quotations, 3. Team details, 4. Implementation timeline. All documents should be in PDF format.'
    },
    
    'status': {
        'keywords': ['status', 'track', 'progress', 'update'],
        'response': 'You can track your application status on the dashboard. The approval process has three stages: 1. Department Coordinator, 2. College Coordinator, 3. Principal.'
    },
    
    'review': {
        'keywords': ['review', 'process', 'approval', 'evaluate', 'assessment'],
        'response': 'The review process: 1. Department coordinator reviews technical aspects, 2. College coordinator verifies project feasibility, 3. Principal gives final approval for funding.'
    }
}

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def send_email(subject, recipient, body):
    """Send an email using Flask-Mail."""
    try:
        msg = Message(
            subject,
            recipients=[recipient],
            body=body
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # student, dept_coord, college_coord, principal
    name = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100))
    
    # Define relationships
    user_applications = db.relationship('Application', back_populates='applicant')
    user_notifications = db.relationship('Notification', back_populates='notification_user')

    def __repr__(self):
        return f'<User {self.email}>'

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    application_number = db.Column(db.String(50), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_title = db.Column(db.String(200), nullable=False)
    problem_statement = db.Column(db.Text, nullable=False)
    solution = db.Column(db.Text, nullable=False)
    team_members = db.Column(db.String(500))
    total_cost = db.Column(db.Float, nullable=False)
    quotation_path = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # New fields for enhanced metrics
    team_size = db.Column(db.Integer, default=1)
    project_duration = db.Column(db.Integer, default=6)  # in months
    completion_percentage = db.Column(db.Integer, default=0)
    innovation_score = db.Column(db.Integer, default=0)  # 0-100
    technical_complexity = db.Column(db.String(20), default='medium')  # low, medium, high
    project_domain = db.Column(db.String(50))
    implementation_status = db.Column(db.String(20), default='planning')  # planning, in-progress, testing, completed
    
    # Status fields
    dept_status = db.Column(db.String(20), default='pending')
    dept_remarks = db.Column(db.Text)
    dept_review_date = db.Column(db.DateTime)
    
    college_status = db.Column(db.String(20), default='pending')
    college_remarks = db.Column(db.Text)
    college_review_date = db.Column(db.DateTime)
    
    principal_status = db.Column(db.String(20), default='pending')
    principal_remarks = db.Column(db.Text)
    principal_review_date = db.Column(db.DateTime)
    
    # Define relationships
    applicant = db.relationship('User', back_populates='user_applications')
    funding_request = db.relationship('FundingRequest', back_populates='ssip_application', uselist=False)
    purchase_lists = db.relationship('PurchaseList', back_populates='application')
    utilization_certificates = db.relationship('UtilizationCertificate', back_populates='application')
    components = db.relationship('Component', back_populates='application')
    application_notifications = db.relationship('Notification', back_populates='related_application')

    def __repr__(self):
        return f'<Application {self.application_number}>'

class PurchaseList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey('application.id'), nullable=False)
    item_name = db.Column(db.String(200), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    estimated_cost = db.Column(db.Float, nullable=False)
    quotation_file = db.Column(db.String(255))  # Path to uploaded quotation file
    dept_status = db.Column(db.String(20), default='pending')
    college_status = db.Column(db.String(20), default='pending')
    principal_status = db.Column(db.String(20), default='pending')
    dept_remarks = db.Column(db.Text)
    college_remarks = db.Column(db.Text)
    principal_remarks = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Update relationship to use back_populates
    application = db.relationship('Application', back_populates='purchase_lists')

class UtilizationCertificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey('application.id'), nullable=False)
    purchase_list_id = db.Column(db.Integer, db.ForeignKey('purchase_list.id'), nullable=False)
    actual_cost = db.Column(db.Float, nullable=False)
    bill_file = db.Column(db.String(255))  # Path to uploaded bill file
    purchase_date = db.Column(db.DateTime, nullable=False)
    dept_status = db.Column(db.String(20), default='pending')
    college_status = db.Column(db.String(20), default='pending')
    principal_status = db.Column(db.String(20), default='pending')
    dept_remarks = db.Column(db.Text)
    college_remarks = db.Column(db.Text)
    principal_remarks = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Update relationship to use back_populates
    application = db.relationship('Application', back_populates='utilization_certificates')

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    application_id = db.Column(db.Integer, db.ForeignKey('application.id'))
    message = db.Column(db.String(500), nullable=False)
    type = db.Column(db.String(50))  # e.g., 'info', 'warning', 'success'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    # Update relationship to use back_populates
    notification_user = db.relationship('User', back_populates='user_notifications')
    related_application = db.relationship('Application', back_populates='application_notifications')

class FundingRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey('application.id'), nullable=False)
    actual_cost = db.Column(db.Float, nullable=False)
    bill_path = db.Column(db.String(200))
    remarks = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    # Status and remarks for each level
    dept_status = db.Column(db.String(20), default='pending')
    dept_remarks = db.Column(db.Text)
    dept_review_date = db.Column(db.DateTime)
    
    college_status = db.Column(db.String(20), default='pending')
    college_remarks = db.Column(db.Text)
    college_review_date = db.Column(db.DateTime)
    
    principal_status = db.Column(db.String(20), default='pending')
    principal_remarks = db.Column(db.Text)
    principal_review_date = db.Column(db.DateTime)
    
    # Update relationship to use back_populates
    ssip_application = db.relationship('Application', back_populates='funding_request')

class Component(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey('application.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    cost_per_unit = db.Column(db.Float, nullable=False)
    application = db.relationship('Application', back_populates='components')

def create_notification(application, user, message, type='info'):
    """Create a notification for a user regarding an application."""
    notification = Notification(
        user_id=user.id,
        application_id=application.id,
        message=message,
        type=type
    )
    db.session.add(notification)
    db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and user.password == password:  # In production, use proper password hashing
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        role = request.form.get('role')
        department = request.form.get('department')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
        
        user = User(email=email, password=password, name=name, role=role, department=department)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'student':
        applications = Application.query.filter_by(user_id=current_user.id).all()
        stats = {
            'total': len(applications),
            'pending': sum(1 for app in applications if app.principal_status == 'pending'),
            'approved': sum(1 for app in applications if app.principal_status == 'approved'),
            'rejected': sum(1 for app in applications if app.principal_status == 'rejected')
        }
    elif current_user.role == 'dept_coord':
        applications = Application.query.join(User).filter(User.department == current_user.department).all()
        stats = {
            'total': len(applications),
            'pending': sum(1 for app in applications if app.dept_status == 'pending'),
            'approved': sum(1 for app in applications if app.dept_status == 'approved'),
            'rejected': sum(1 for app in applications if app.dept_status == 'rejected')
        }
    elif current_user.role == 'college_coord':
        applications = Application.query.all()
        stats = {
            'total': len(applications),
            'pending': sum(1 for app in applications if app.college_status == 'pending' and app.dept_status == 'approved'),
            'approved': sum(1 for app in applications if app.college_status == 'approved'),
            'rejected': sum(1 for app in applications if app.college_status == 'rejected')
        }
    else:  # principal
        applications = Application.query.all()
        stats = {
            'total': len(applications),
            'pending': sum(1 for app in applications if app.principal_status == 'pending' and app.college_status == 'approved'),
            'approved': sum(1 for app in applications if app.principal_status == 'approved'),
            'rejected': sum(1 for app in applications if app.principal_status == 'rejected')
        }

    return render_template('dashboard.html', applications=applications, stats=stats)

from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, DecimalField, SubmitField
from wtforms.validators import DataRequired, NumberRange

class ApplicationForm(FlaskForm):
    project_title = StringField('Project Title', validators=[DataRequired()])
    problem_statement = TextAreaField('Problem Statement', validators=[DataRequired()])
    solution = TextAreaField('Proposed Solution', validators=[DataRequired()])
    team_members = StringField('Team Members', validators=[DataRequired()])
    total_cost = DecimalField('Total Cost', validators=[DataRequired(), NumberRange(min=0)])
    submit = SubmitField('Submit Application')

@app.route('/submit_application', methods=['GET', 'POST'])
@login_required
def submit_application():
    if request.method == 'POST':
        # Generate unique application number
        application_number = f"SSIP{int(time.time())}"
        
        # Create new application
        application = Application(
            application_number=application_number,
            user_id=current_user.id,
            project_title=request.form.get('project_title'),
            problem_statement=request.form.get('problem_statement'),
            solution=request.form.get('solution'),
            team_members=request.form.get('team_members'),
            team_size=int(request.form.get('team_size', 1)),
            project_duration=int(request.form.get('project_duration', 6)),
            project_domain=request.form.get('project_domain'),
            technical_complexity=request.form.get('technical_complexity'),
            total_cost=float(request.form.get('total_cost')),
            completion_percentage=0,
            innovation_score=0,
            implementation_status='planning'
        )
        
        # Handle quotation file
        if 'quotation' in request.files:
            quotation = request.files['quotation']
            if quotation.filename:
                filename = secure_filename(quotation.filename)
                quotation_path = os.path.join('uploads', 'quotations', filename)
                quotation.save(os.path.join(app.root_path, 'static', quotation_path))
                application.quotation_path = quotation_path
        
        try:
            db.session.add(application)
            db.session.commit()
            
            # Create notification for department coordinator
            dept_coord = User.query.filter_by(role='dept_coord', department=current_user.department).first()
            if dept_coord:
                notification = Notification(
                    user_id=dept_coord.id,
                    application_id=application.id,
                    message=f'New SSIP application ({application_number}) requires review',
                    type='new_application'
                )
                db.session.add(notification)
                db.session.commit()
                
                # Send email notification
                email_body = f"""
                Dear Department Coordinator,

                A new SSIP application ({application_number}) has been submitted and requires your review.
                
                Project Details:
                - Title: {application.project_title}
                - Domain: {application.project_domain}
                - Total Cost: ₹{application.total_cost}
                
                Please login to the SSIP portal to review the application.
                
                Best regards,
                SSIP Portal Team
                """
                send_email('New SSIP Application Submitted', dept_coord.email, email_body)
            
            flash('Application submitted successfully', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Error submitting application. Please try again.', 'error')
            print(f"Error: {str(e)}")
            return redirect(url_for('submit_application'))
    
    return render_template('submit_application.html')

@app.route('/application/<int:id>')
@login_required
def view_application(id):
    application = Application.query.get_or_404(id)
    components = Component.query.filter_by(application_id=id).all()
    return render_template('view_application.html', 
                         application=application,
                         components=components)

@app.route('/application/<int:id>/mentor/approve/<token>', methods=['GET', 'POST'])
def mentor_approve_application(id, token):
    application = Application.query.get_or_404(id)
    
    try:
        # Verify token (expires in 7 days)
        mentor_email = serializer.loads(token, salt='mentor-approval', max_age=604800)
        if mentor_email != application.mentor_email:
            flash('Invalid approval link', 'danger')
            return redirect(url_for('index'))
    except:
        flash('Invalid or expired approval link', 'danger')
        return redirect(url_for('index'))
    
    if application.mentor_approval:
        flash('This application has already been reviewed by the mentor', 'info')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        try:
            action = request.form.get('action')
            remarks = request.form.get('remarks', '')
            
            if action == 'approve':
                application.mentor_approval = True
                application.mentor_approval_date = datetime.utcnow()
                
                # Notify student
                student_msg = f'Your application {application.application_number} has been approved by mentor'
                create_notification(application, application.applicant, student_msg, type='approval')
                send_email(
                    'Application Approved by Mentor',
                    application.applicant.email,
                    student_msg
                )
                
                # Find department coordinator
                dept_coord = User.query.filter_by(role='department_coordinator', department=application.applicant.department).first()
                if dept_coord:
                    # Notify department coordinator
                    coord_msg = f'New application {application.application_number} requires your review'
                    create_notification(application, dept_coord, coord_msg, type='pending')
                    send_email(
                        'New Application Requires Review',
                        dept_coord.email,
                        coord_msg
                    )
                
                flash('Application approved successfully', 'success')
            else:
                # Notify student of rejection
                student_msg = f'Your application {application.application_number} has been rejected by mentor'
                if remarks:
                    student_msg += f'\nRemarks: {remarks}'
                
                create_notification(application, application.applicant, student_msg, type='rejection')
                send_email(
                    'Application Rejected by Mentor',
                    application.applicant.email,
                    student_msg
                )
                
                flash('Application rejected', 'info')
            
            db.session.commit()
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Error processing approval: ' + str(e), 'danger')
            return redirect(url_for('mentor_approve_application', id=id, token=token))
    
    return render_template('mentor_approval.html', application=application)

@app.route('/application/<int:id>/dept/approve', methods=['POST'])
@login_required
def approve_dept(id):
    if current_user.role != 'dept_coord':
        flash('You do not have permission to approve applications.', 'danger')
        return redirect(url_for('dashboard'))
    
    application = Application.query.get_or_404(id)
    
    if application.dept_status != 'pending':
        flash('Application has already been processed.', 'warning')
        return redirect(url_for('dashboard'))
    
    application.dept_status = 'approved'
    application.dept_review_date = datetime.utcnow()
    
    # Create notification for student
    notification = Notification(
        application_id=application.id,
        user_id=application.user_id,
        message='Your application has been approved by the department coordinator.',
        type='success'
    )
    db.session.add(notification)
    
    db.session.commit()
    flash('Application approved successfully.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/reject_dept/<int:id>', methods=['POST'])
@login_required
def reject_dept(id):
    application = Application.query.get_or_404(id)
    if current_user.role != 'dept_coord':
        flash('You do not have permission to reject this application', 'error')
        return redirect(url_for('view_application', id=id))
    
    remarks = request.form.get('remarks', '')
    application.dept_status = 'rejected'
    application.dept_remarks = remarks
    application.dept_review_date = datetime.now()
    
    # Create notification for student
    create_notification(
        application=application,
        user=application.applicant,
        message=f'Your application {application.application_number} has been rejected by department coordinator',
        type='error'
    )
    
    db.session.commit()
    flash('Application has been rejected', 'warning')
    return redirect(url_for('view_application', id=id))

@app.route('/application/<int:id>/college/approve', methods=['POST'])
@login_required
def approve_college(id):
    if current_user.role != 'college_coord':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    application = Application.query.get_or_404(id)
    if application.dept_status != 'approved':
        flash('Application must be approved by department first', 'danger')
        return redirect(url_for('dashboard'))
    
    application.college_status = 'approved'
    application.college_review_date = datetime.utcnow()
    
    # Create notification for student
    student_notification = Notification(
        application_id=application.id,
        user_id=application.user_id,
        message='Your application has been approved by the college coordinator.',
        type='success'
    )
    db.session.add(student_notification)
    
    # Create notification for principal
    principal = User.query.filter_by(role='principal').first()
    if principal:
        principal_notification = Notification(
            application_id=application.id,
            user_id=principal.id,
            message=f'Application {application.application_number} requires your review.',
            type='info'
        )
        db.session.add(principal_notification)
    
    db.session.commit()
    flash('Application approved successfully.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/reject_college/<int:id>', methods=['POST'])
@login_required
def reject_college(id):
    application = Application.query.get_or_404(id)
    if current_user.role != 'college_coord':
        flash('You do not have permission to reject this application', 'error')
        return redirect(url_for('view_application', id=id))
    
    if application.dept_status != 'approved':
        flash('Department approval is required first', 'error')
        return redirect(url_for('view_application', id=id))
    
    remarks = request.form.get('remarks', '')
    application.college_status = 'rejected'
    application.college_remarks = remarks
    application.college_review_date = datetime.now()
    
    # Create notification for student
    create_notification(
        application=application,
        user=application.applicant,
        message=f'Your application {application.application_number} has been rejected by college coordinator',
        type='error'
    )
    
    db.session.commit()
    flash('Application has been rejected', 'warning')
    return redirect(url_for('view_application', id=id))

@app.route('/application/<int:id>/principal/approve', methods=['POST'])
@login_required
def approve_principal(id):
    if current_user.role != 'principal':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    application = Application.query.get_or_404(id)
    if application.college_status != 'approved':
        flash('Application must be approved by college first', 'danger')
        return redirect(url_for('dashboard'))
    
    application.principal_status = 'approved'
    application.principal_review_date = datetime.utcnow()
    
    # Create notification for student
    notification = Notification(
        application_id=application.id,
        user_id=application.user_id,
        message='Your application has been approved by the principal.',
        type='success'
    )
    db.session.add(notification)
    
    db.session.commit()
    flash('Application approved successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/reject_principal/<int:id>', methods=['POST'])
@login_required
def reject_principal(id):
    application = Application.query.get_or_404(id)
    if current_user.role != 'principal':
        flash('You do not have permission to reject this application', 'error')
        return redirect(url_for('view_application', id=id))
    
    if application.dept_status != 'approved' or application.college_status != 'approved':
        flash('Both department and college approval are required first', 'error')
        return redirect(url_for('view_application', id=id))
    
    remarks = request.form.get('remarks', '')
    application.principal_status = 'rejected'
    application.principal_remarks = remarks
    application.principal_review_date = datetime.now()
    
    # Create notification for student
    create_notification(
        application=application,
        user=application.applicant,
        message=f'Your application {application.application_number} has been rejected by principal',
        type='error'
    )
    
    db.session.commit()
    flash('Application has been rejected', 'warning')
    return redirect(url_for('view_application', id=id))

@app.route('/application/<int:id>/purchase-list', methods=['GET', 'POST'])
@login_required
def purchase_list(id):
    application = Application.query.get_or_404(id)
    # Only allow if application is approved
    if application.principal_status != 'approved':
        flash('Purchase list can only be created for approved applications', 'danger')
        return redirect(url_for('view_application', id=id))
    
    if request.method == 'POST':
        item_name = request.form.get('item_name')
        quantity = int(request.form.get('quantity'))
        estimated_cost = float(request.form.get('estimated_cost'))
        
        # Handle quotation file upload
        quotation_file = request.files.get('quotation_file')
        if quotation_file:
            filename = f'quotation_{application.application_number}_{datetime.utcnow().strftime("%Y%m%d%H%M%S")}.pdf'
            quotation_file.save(os.path.join('uploads', 'quotations', filename))
        else:
            filename = None
        
        purchase_list = PurchaseList(
            application_id=id,
            item_name=item_name,
            quantity=quantity,
            estimated_cost=estimated_cost,
            quotation_file=filename
        )
        
        db.session.add(purchase_list)
        db.session.commit()
        
        flash('Purchase list item added successfully', 'success')
        return redirect(url_for('purchase_list', id=id))
    
    purchase_items = PurchaseList.query.filter_by(application_id=id).all()
    return render_template('purchase_list.html', application=application, items=purchase_items)

# Purchase List Approval Routes
@app.route('/purchase-item/<int:id>/dept/approve', methods=['POST'])
@login_required
def approve_purchase_item_dept(id):
    if current_user.role != 'dept_coord':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    item = PurchaseList.query.get_or_404(id)
    item.dept_status = 'approved'
    db.session.commit()
    flash('Purchase item approved by department', 'success')
    return redirect(url_for('dashboard'))

@app.route('/purchase-item/<int:id>/dept/reject', methods=['POST'])
@login_required
def reject_purchase_item_dept(id):
    if current_user.role != 'dept_coord':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    item = PurchaseList.query.get_or_404(id)
    item.dept_status = 'rejected'
    item.dept_remarks = request.form.get('remarks')
    db.session.commit()
    flash('Purchase item rejected by department', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/purchase-item/<int:id>/college/approve', methods=['POST'])
@login_required
def approve_purchase_item_college(id):
    if current_user.role != 'college_coord':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    item = PurchaseList.query.get_or_404(id)
    if item.dept_status != 'approved':
        flash('Item must be approved by department first', 'danger')
        return redirect(url_for('dashboard'))
    
    item.college_status = 'approved'
    db.session.commit()
    flash('Purchase item approved by college', 'success')
    return redirect(url_for('dashboard'))

@app.route('/purchase-item/<int:id>/college/reject', methods=['POST'])
@login_required
def reject_purchase_item_college(id):
    if current_user.role != 'college_coord':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    item = PurchaseList.query.get_or_404(id)
    if item.dept_status != 'approved':
        flash('Item must be approved by department first', 'danger')
        return redirect(url_for('dashboard'))
    
    item.college_status = 'rejected'
    item.college_remarks = request.form.get('remarks')
    db.session.commit()
    flash('Purchase item rejected by college', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/purchase-item/<int:id>/principal/approve', methods=['POST'])
@login_required
def approve_purchase_item_principal(id):
    if current_user.role != 'principal':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    item = PurchaseList.query.get_or_404(id)
    if item.dept_status != 'approved' or item.college_status != 'approved':
        flash('Item must be approved by department and college first', 'danger')
        return redirect(url_for('dashboard'))
    
    item.principal_status = 'approved'
    db.session.commit()
    flash('Purchase item approved by principal', 'success')
    return redirect(url_for('dashboard'))

@app.route('/purchase-item/<int:id>/principal/reject', methods=['POST'])
@login_required
def reject_purchase_item_principal(id):
    if current_user.role != 'principal':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    item = PurchaseList.query.get_or_404(id)
    if item.dept_status != 'approved' or item.college_status != 'approved':
        flash('Item must be approved by department and college first', 'danger')
        return redirect(url_for('dashboard'))
    
    item.principal_status = 'rejected'
    item.principal_remarks = request.form.get('remarks')
    db.session.commit()
    flash('Purchase item rejected by principal', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/purchase-list/<int:id>/approve', methods=['POST'])
@login_required
def approve_purchase_item(id):
    if current_user.role not in ['dept_coord', 'college_coord', 'principal']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    item = PurchaseList.query.get_or_404(id)
    item.status = 'approved'
    item.remarks = request.form.get('remarks')
    db.session.commit()
    
    flash('Purchase item approved', 'success')
    return redirect(url_for('purchase_list', id=item.application_id))

@app.route('/purchase-list/<int:id>/reject', methods=['POST'])
@login_required
def reject_purchase_item(id):
    if current_user.role not in ['dept_coord', 'college_coord', 'principal']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    item = PurchaseList.query.get_or_404(id)
    item.status = 'rejected'
    item.remarks = request.form.get('remarks')
    db.session.commit()
    
    flash('Purchase item rejected', 'success')
    return redirect(url_for('purchase_list', id=item.application_id))

@app.route('/application/<int:id>/utilization', methods=['GET', 'POST'])
@login_required
def utilization_certificate(id):
    application = Application.query.get_or_404(id)
    # Get purchase items that are approved by all levels
    purchase_items = PurchaseList.query.filter_by(
        application_id=id,
        dept_status='approved',
        college_status='approved',
        principal_status='approved'
    ).all()
    
    if request.method == 'POST':
        purchase_list_id = request.form.get('purchase_list_id')
        actual_cost = float(request.form.get('actual_cost'))
        purchase_date = datetime.strptime(request.form.get('purchase_date'), '%Y-%m-%d')
        
        # Handle bill file upload
        bill_file = request.files.get('bill_file')
        if bill_file:
            filename = f'bill_{application.application_number}_{datetime.utcnow().strftime("%Y%m%d%H%M%S")}.pdf'
            bill_file.save(os.path.join('uploads', 'bills', filename))
        else:
            filename = None
        
        certificate = UtilizationCertificate(
            application_id=id,
            purchase_list_id=purchase_list_id,
            actual_cost=actual_cost,
            bill_file=filename,
            purchase_date=purchase_date,
            user_id=current_user.id
        )
        
        db.session.add(certificate)
        db.session.commit()
        
        flash('Utilization certificate submitted successfully', 'success')
        return redirect(url_for('utilization_certificate', id=id))
    
    certificates = UtilizationCertificate.query.filter_by(application_id=id).all()
    return render_template('utilization_certificate.html',
                         application=application,
                         purchase_items=purchase_items,
                         certificates=certificates)

# Utilization Certificate Approval Routes
@app.route('/utilization/<int:id>/dept/approve', methods=['POST'])
@login_required
def approve_utilization_dept(id):
    if current_user.role != 'dept_coord':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    utilization = UtilizationCertificate.query.get_or_404(id)
    utilization.dept_status = 'approved'
    db.session.commit()
    flash('Utilization certificate approved by department', 'success')
    return redirect(url_for('dashboard'))

@app.route('/utilization/<int:id>/dept/reject', methods=['POST'])
@login_required
def reject_utilization_dept(id):
    if current_user.role != 'dept_coord':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    utilization = UtilizationCertificate.query.get_or_404(id)
    utilization.dept_status = 'rejected'
    utilization.dept_remarks = request.form.get('remarks')
    db.session.commit()
    flash('Utilization certificate rejected by department', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/utilization/<int:id>/college/approve', methods=['POST'])
@login_required
def approve_utilization_college(id):
    if current_user.role != 'college_coord':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    utilization = UtilizationCertificate.query.get_or_404(id)
    if utilization.dept_status != 'approved':
        flash('Certificate must be approved by department first', 'danger')
        return redirect(url_for('dashboard'))
    
    utilization.college_status = 'approved'
    db.session.commit()
    flash('Utilization certificate approved by college', 'success')
    return redirect(url_for('dashboard'))

@app.route('/utilization/<int:id>/college/reject', methods=['POST'])
@login_required
def reject_utilization_college(id):
    if current_user.role != 'college_coord':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    utilization = UtilizationCertificate.query.get_or_404(id)
    if utilization.dept_status != 'approved':
        flash('Certificate must be approved by department first', 'danger')
        return redirect(url_for('dashboard'))
    
    utilization.college_status = 'rejected'
    utilization.college_remarks = request.form.get('remarks')
    db.session.commit()
    flash('Utilization certificate rejected by college', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/utilization/<int:id>/principal/approve', methods=['POST'])
@login_required
def approve_utilization_principal(id):
    if current_user.role != 'principal':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    utilization = UtilizationCertificate.query.get_or_404(id)
    if utilization.dept_status != 'approved' or utilization.college_status != 'approved':
        flash('Certificate must be approved by department and college first', 'danger')
        return redirect(url_for('dashboard'))
    
    utilization.principal_status = 'approved'
    db.session.commit()
    flash('Utilization certificate approved by principal', 'success')
    return redirect(url_for('dashboard'))

@app.route('/utilization/<int:id>/principal/reject', methods=['POST'])
@login_required
def reject_utilization_principal(id):
    if current_user.role != 'principal':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    utilization = UtilizationCertificate.query.get_or_404(id)
    if utilization.dept_status != 'approved' or utilization.college_status != 'approved':
        flash('Certificate must be approved by department and college first', 'danger')
        return redirect(url_for('dashboard'))
    
    utilization.principal_status = 'rejected'
    utilization.principal_remarks = request.form.get('remarks')
    db.session.commit()
    flash('Utilization certificate rejected by principal', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/utilization/<int:id>/verify', methods=['POST'])
@login_required
def verify_utilization(id):
    if current_user.role != 'dept_coord':
        flash('Only department coordinators can verify utilization certificates', 'danger')
        return redirect(url_for('dashboard'))
    
    certificate = UtilizationCertificate.query.get_or_404(id)
    certificate.verification_status = 'verified'
    certificate.coordinator_remarks = request.form.get('remarks')
    db.session.commit()
    
    flash('Utilization certificate verified', 'success')
    return redirect(url_for('utilization_certificate', id=certificate.application_id))

@app.route('/application/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_application(id):
    application = Application.query.get_or_404(id)
    
    # Only allow editing if the application belongs to the current user and is rejected
    if current_user.id != application.user_id or application.dept_status != 'rejected':
        flash('You cannot edit this application', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            # Update application details
            application.project_title = request.form.get('project_title')
            application.problem_statement = request.form.get('problem_statement')
            application.solution = request.form.get('solution')
            
            # Convert team members list to JSON string
            team_members = request.form.getlist('team_members[]')
            application.team_members = json.dumps(team_members)
            
            # Update components and calculate total cost
            components = []
            total_cost = 0
            component_names = request.form.getlist('component[]')
            component_costs = request.form.getlist('cost[]')
            
            for name, cost in zip(component_names, component_costs):
                if name and cost:
                    components.append({'name': name, 'cost': float(cost)})
                    total_cost += float(cost)
            
            # Convert components list to JSON string
            application.required_components = json.dumps(components)
            application.total_cost = total_cost
            
            # Reset the application status to pending
            application.dept_status = 'pending'
            application.dept_remarks = None
            
            db.session.commit()
            flash('Application updated successfully', 'success')
            return redirect(url_for('view_application', id=id))
        except Exception as e:
            db.session.rollback()
            flash('Error updating application: ' + str(e), 'danger')
    
    return render_template('edit_application.html', application=application)

@app.route('/new_funding_application/<int:application_id>', methods=['GET', 'POST'])
@login_required
def new_funding_application(application_id):
    application = Application.query.get_or_404(application_id)
    
    # Check if user owns this application or has appropriate role
    if not (current_user.id == application.user_id or current_user.role in ['dept_coord', 'college_coord', 'principal']):
        flash('You do not have permission to access this application', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check if application is approved by principal
    if application.principal_status != 'approved':
        flash('Application must be approved by principal before submitting funding request', 'error')
        return redirect(url_for('view_application', id=application_id))
    
    # Check if funding application already exists
    if FundingRequest.query.filter_by(application_id=application_id).first():
        flash('Funding application already exists for this project', 'warning')
        return redirect(url_for('view_application', id=application_id))
    
    if request.method == 'POST':
        funding = FundingRequest(
            application_id=application_id,
            required_components=request.form.get('required_components'),
            total_cost=float(request.form.get('total_cost'))
        )
        db.session.add(funding)
        db.session.commit()
        
        flash('Funding application submitted successfully', 'success')
        return redirect(url_for('view_funding_application', id=funding.id))
    
    return render_template('new_funding_application.html', application=application)

@app.route('/view_funding_application/<int:id>')
@login_required
def view_funding_application(id):
    funding = FundingRequest.query.get_or_404(id)
    application = funding.ssip_application
    
    # Check if user owns this application or has appropriate role
    if not (current_user.id == application.user_id or current_user.role in ['dept_coord', 'college_coord', 'principal']):
        flash('You do not have permission to access this application', 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('view_funding_application.html', funding=funding, application=application)

@app.route('/approve_funding_dept/<int:id>', methods=['POST'])
@login_required
def approve_funding_dept(id):
    if current_user.role != 'dept_coord':
        flash('You do not have permission to approve department funding', 'danger')
        return redirect(url_for('dashboard'))
    
    funding = FundingRequest.query.get_or_404(id)
    funding.dept_status = 'approved'
    funding.dept_remarks = request.form.get('remarks')
    funding.dept_review_date = datetime.utcnow()
    db.session.commit()
    
    flash('Funding application approved at department level', 'success')
    return redirect(url_for('view_funding_application', id=id))

@app.route('/approve_funding_college/<int:id>', methods=['POST'])
@login_required
def approve_funding_college(id):
    if current_user.role != 'college_coord':
        flash('You do not have permission to approve college funding', 'danger')
        return redirect(url_for('dashboard'))
    
    funding = FundingRequest.query.get_or_404(id)
    
    if funding.dept_status != 'approved':
        flash('Funding must be approved by department first', 'warning')
        return redirect(url_for('view_funding_application', id=id))
    
    funding.college_status = 'approved'
    funding.college_remarks = request.form.get('remarks')
    funding.college_review_date = datetime.utcnow()
    db.session.commit()
    
    flash('Funding application approved at college level', 'success')
    return redirect(url_for('view_funding_application', id=id))

@app.route('/approve_funding_principal/<int:id>', methods=['POST'])
@login_required
def approve_funding_principal(id):
    if current_user.role != 'principal':
        flash('You do not have permission to approve principal funding', 'danger')
        return redirect(url_for('dashboard'))
    
    funding = FundingRequest.query.get_or_404(id)
    
    if funding.college_status != 'approved':
        flash('Funding must be approved by college first', 'warning')
        return redirect(url_for('view_funding_application', id=id))
    
    funding.principal_status = 'approved'
    funding.principal_remarks = request.form.get('remarks')
    funding.principal_review_date = datetime.utcnow()
    db.session.commit()
    
    flash('Funding application approved by principal', 'success')
    return redirect(url_for('view_funding_application', id=id))

@app.route('/resubmit_application/<int:id>', methods=['GET', 'POST'])
@login_required
def resubmit_application(id):
    application = Application.query.get_or_404(id)
    if request.method == 'POST':
        # Update application with new information
        application.project_title = request.form.get('project_title')
        application.problem_statement = request.form.get('problem_statement')
        application.solution = request.form.get('solution')
        application.team_members = request.form.get('team_members')
        
        # Handle components and cost
        components = []
        total_cost = 0
        component_names = request.form.getlist('component_name[]')
        component_costs = request.form.getlist('component_cost[]')
        
        for name, cost in zip(component_names, component_costs):
            if name and cost:
                components.append(f"{name}: {cost}")
                total_cost += float(cost)
        
        application.required_components = '\n'.join(components)
        application.total_cost = total_cost
        
        # Reset status
        application.dept_status = 'pending'
        application.dept_remarks = None
        application.dept_review_date = None
        application.college_status = 'pending'
        application.college_remarks = None
        application.college_review_date = None
        application.principal_status = 'pending'
        application.principal_remarks = None
        application.principal_review_date = None
        
        db.session.commit()
        flash('Application resubmitted successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('resubmit_application.html', application=application)

@app.route('/submit_funding/<int:application_id>', methods=['GET', 'POST'])
@login_required
def submit_funding(application_id):
    application = Application.query.get_or_404(application_id)
    if request.method == 'POST':
        # Create new funding application
        funding = FundingRequest(
            application_id=application.id,
            actual_cost=float(request.form.get('actual_cost')),
            remarks=request.form.get('remarks')
        )
        
        # Handle bill upload
        if 'bill' in request.files:
            bill = request.files['bill']
            if bill.filename:
                # Create directory if it doesn't exist
                bill_dir = os.path.join(app.root_path, 'static', 'uploads', 'bills')
                os.makedirs(bill_dir, exist_ok=True)
                
                # Save bill with secure filename
                filename = secure_filename(f"{application.application_number}_bill_{bill.filename}")
                bill.save(os.path.join(bill_dir, filename))
                funding.bill_path = os.path.join('uploads', 'bills', filename)
        
        db.session.add(funding)
        db.session.commit()
        
        flash('Funding application submitted successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('submit_funding.html', application=application)

@app.route('/view_funding/<int:id>')
@login_required
def view_funding(id):
    funding = FundingRequest.query.get_or_404(id)
    return render_template('view_funding.html', funding=funding)

@app.route('/dept_review_funding/<int:id>', methods=['POST'])
@login_required
def dept_review_funding(id):
    if not current_user.is_dept_coordinator:
        abort(403)
    
    funding = FundingRequest.query.get_or_404(id)
    action = request.form.get('action')
    remarks = request.form.get('remarks')
    
    if action == 'approve':
        funding.dept_status = 'approved'
        msg_type = 'success'
        message = 'Funding request approved by department coordinator'
    else:
        funding.dept_status = 'rejected'
        msg_type = 'danger'
        message = 'Funding request rejected by department coordinator'
    
    funding.dept_remarks = remarks
    funding.dept_review_date = datetime.utcnow()
    db.session.commit()
    
    create_notification(funding.ssip_application, funding.ssip_application.applicant, message)
    flash(message, msg_type)
    return redirect(url_for('view_funding', id=id))

@app.route('/college_review_funding/<int:id>', methods=['POST'])
@login_required
def college_review_funding(id):
    if not current_user.is_college_coordinator:
        abort(403)
    
    funding = FundingRequest.query.get_or_404(id)
    if funding.dept_status != 'approved':
        flash('Funding request must be approved by department coordinator first', 'danger')
        return redirect(url_for('view_funding', id=id))
    
    action = request.form.get('action')
    remarks = request.form.get('remarks')
    
    if action == 'approve':
        funding.college_status = 'approved'
        msg_type = 'success'
        message = 'Funding request approved by college coordinator'
    else:
        funding.college_status = 'rejected'
        msg_type = 'danger'
        message = 'Funding request rejected by college coordinator'
    
    funding.college_remarks = remarks
    funding.college_review_date = datetime.utcnow()
    db.session.commit()
    
    create_notification(funding.ssip_application, funding.ssip_application.applicant, message)
    flash(message, msg_type)
    return redirect(url_for('view_funding', id=id))

@app.route('/principal_review_funding/<int:id>', methods=['POST'])
@login_required
def principal_review_funding(id):
    if not current_user.is_principal:
        abort(403)
    
    funding = FundingRequest.query.get_or_404(id)
    if funding.college_status != 'approved':
        flash('Funding request must be approved by college coordinator first', 'danger')
        return redirect(url_for('view_funding', id=id))
    
    action = request.form.get('action')
    remarks = request.form.get('remarks')
    
    if action == 'approve':
        funding.principal_status = 'approved'
        msg_type = 'success'
        message = 'Funding request approved by principal'
    else:
        funding.principal_status = 'rejected'
        msg_type = 'danger'
        message = 'Funding request rejected by principal'
    
    funding.principal_remarks = remarks
    funding.principal_review_date = datetime.utcnow()
    db.session.commit()
    
    create_notification(funding.ssip_application, funding.ssip_application.applicant, message)
    flash(message, msg_type)
    return redirect(url_for('view_funding', id=id))

@app.route('/funding-application/submit/<int:application_id>', methods=['GET', 'POST'])
@login_required
def submit_funding_application(application_id):
    application = Application.query.get_or_404(application_id)
    funding = FundingRequest.query.filter_by(application_id=application_id).first()
    
    if request.method == 'POST':
        if not funding:
            funding = FundingRequest(
                application_id=application_id,
                actual_cost=float(request.form.get('actual_cost')),
                remarks=request.form.get('remarks')
            )
            
            # Handle bill upload
            if 'bill' in request.files:
                bill = request.files['bill']
                if bill.filename:
                    # Create directory if it doesn't exist
                    bill_dir = os.path.join(app.root_path, 'static', 'uploads', 'bills')
                    os.makedirs(bill_dir, exist_ok=True)
                    
                    # Save bill with secure filename
                    filename = secure_filename(f"{application.application_number}_bill_{bill.filename}")
                    bill.save(os.path.join(bill_dir, filename))
                    funding.bill_path = os.path.join('uploads', 'bills', filename)
            
            db.session.add(funding)
            db.session.commit()
            
            # Create notification for department coordinator
            dept_coord = User.query.filter_by(role='dept_coord', department=current_user.department).first()
            if dept_coord:
                create_notification(
                    application,
                    dept_coord,
                    f'New funding application submitted for {application.application_number}',
                    'info'
                )
            
            flash('Funding application submitted successfully!', 'success')
            return redirect(url_for('view_funding_application', id=funding.id))
    
    return render_template('submit_funding.html', application=application, funding=funding)

@app.route('/funding-application/status/<int:funding_id>')
@login_required
def funding_application_status(funding_id):
    funding = FundingRequest.query.get_or_404(funding_id)
    application = funding.ssip_application
    
    # Check if user has permission to view this funding application
    if not (current_user.id == application.user_id or 
            current_user.role in ['dept_coord', 'college_coord', 'principal']):
        flash('You do not have permission to view this funding application', 'danger')
        return redirect(url_for('dashboard'))
    
    statuses = {
        'dept': {
            'status': funding.dept_status,
            'remarks': funding.dept_remarks,
            'review_date': funding.dept_review_date,
            'coordinator': 'Department Coordinator'
        },
        'college': {
            'status': funding.college_status,
            'remarks': funding.college_remarks,
            'review_date': funding.college_review_date,
            'coordinator': 'College Coordinator'
        },
        'principal': {
            'status': funding.principal_status,
            'remarks': funding.principal_remarks,
            'review_date': funding.principal_review_date,
            'coordinator': 'Principal'
        }
    }
    
    return render_template(
        'funding_status.html',
        funding=funding,
        application=application,
        statuses=statuses
    )

@app.route('/approve_application/<int:id>/<string:level>', methods=['POST'])
@login_required
def approve_application(id, level):
    application = Application.query.get_or_404(id)
    remarks = request.form.get('remarks', '')
    
    if level == 'dept' and current_user.role == 'dept_coord':
        application.dept_status = 'approved'
        application.dept_remarks = remarks
        application.dept_review_date = datetime.now()
        
        # Notify college coordinator
        college_coord = User.query.filter_by(role='college_coord').first()
        if college_coord:
            create_notification(
                application=application,
                user=college_coord,
                message=f'Application {application.application_number} approved by department, pending your review',
                type='info'
            )
            
    elif level == 'college' and current_user.role == 'college_coord':
        # Can only approve if department has approved
        if application.dept_status != 'approved':
            flash('Department approval is required first', 'danger')
            return redirect(url_for('view_application', id=id))
            
        application.college_status = 'approved'
        application.college_remarks = remarks
        application.college_review_date = datetime.now()
        
        # Notify principal
        principal = User.query.filter_by(role='principal').first()
        if principal:
            create_notification(
                application=application,
                user=principal,
                message=f'Application {application.application_number} approved by college, pending your review',
                type='info'
            )
            
    elif level == 'principal' and current_user.role == 'principal':
        # Can only approve if both department and college have approved
        if application.dept_status != 'approved' or application.college_status != 'approved':
            flash('Both department and college approval are required first', 'error')
            return redirect(url_for('view_application', id=id))
            
        application.principal_status = 'approved'
        application.principal_remarks = remarks
        application.principal_review_date = datetime.now()
        
        # Notify student
        create_notification(
            application=application,
            user=application.applicant,
            message=f'Congratulations! Your application {application.application_number} has been fully approved',
            type='success'
        )
    else:
        flash('You do not have permission to perform this action', 'error')
        return redirect(url_for('view_application', id=id))
    
    db.session.commit()
    flash('Application status updated successfully', 'success')
    return redirect(url_for('view_application', id=id))

@app.route('/reject_application/<int:id>/<string:level>', methods=['POST'])
@login_required
def reject_application(id, level):
    application = Application.query.get_or_404(id)
    remarks = request.form.get('remarks', '')
    
    # Check if application exists and user has permission
    if not application:
        flash('Application not found', 'error')
        return redirect(url_for('dashboard'))
        
    if level == 'dept' and current_user.role == 'dept_coord':
        application.dept_status = 'rejected'
        application.dept_remarks = remarks
        application.dept_review_date = datetime.now()
    elif level == 'college' and current_user.role == 'college_coord':
        # Can only reject if department has approved
        if application.dept_status != 'approved':
            flash('Department approval is required first', 'error')
            return redirect(url_for('view_application', id=id))
        application.college_status = 'rejected'
        application.college_remarks = remarks
        application.college_review_date = datetime.now()
    elif level == 'principal' and current_user.role == 'principal':
        # Can only reject if both department and college have approved
        if application.dept_status != 'approved' or application.college_status != 'approved':
            flash('Both department and college approval are required first', 'error')
            return redirect(url_for('view_application', id=id))
        application.principal_status = 'rejected'
        application.principal_remarks = remarks
        application.principal_review_date = datetime.now()
    else:
        flash('You do not have permission to perform this action', 'error')
        return redirect(url_for('view_application', id=id))
    
    # Notify student of rejection
    create_notification(
        application=application,
        user=application.applicant,
        message=f'Your application {application.application_number} has been rejected at {level} level. Please check remarks.',
        type='error'
    )
    
    db.session.commit()
    flash('Application has been rejected', 'warning')
    return redirect(url_for('view_application', id=id))

@app.route('/application/<int:id>/funding/request', methods=['GET', 'POST'])
@login_required
def request_funding(id):
    application = Application.query.get_or_404(id)
    
    # Check if user owns this application
    if application.user_id != current_user.id:
        flash('You do not have permission to request funding for this application', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if application is approved by principal
    if application.principal_status != 'approved':
        flash('Application must be approved by principal before requesting funding', 'error')
        return redirect(url_for('view_application', id=id))
    
    # Check if funding request already exists
    existing_request = FundingRequest.query.filter_by(application_id=id).first()
    
    if request.method == 'POST':
        if existing_request:
            flash('A funding request already exists for this application', 'error')
            return redirect(url_for('view_application', id=id))
        
        actual_cost = float(request.form.get('actual_cost'))
        remarks = request.form.get('remarks')
        bill = request.files.get('bill')
        
        if bill:
            # Create directory if it doesn't exist
            bill_dir = os.path.join(app.root_path, 'static', 'uploads', 'bills')
            os.makedirs(bill_dir, exist_ok=True)
            
            # Save bill with secure filename
            filename = secure_filename(f"{application.application_number}_bill_{int(time.time())}{os.path.splitext(bill.filename)[1]}")
            bill_path = os.path.join('uploads', 'bills', filename)
            bill.save(os.path.join(app.root_path, 'static', bill_path))
        else:
            bill_path = None
        
        funding_request = FundingRequest(
            application_id=id,
            actual_cost=actual_cost,
            bill_path=bill_path,
            remarks=remarks
        )
        
        db.session.add(funding_request)
        db.session.commit()
        
        flash('Funding request submitted successfully', 'success')
        return redirect(url_for('view_application', id=id))
    
    return render_template('funding_request.html', 
                         application=application,
                         funding_request=existing_request)

@app.route('/funding/<int:id>/dept/review', methods=['GET', 'POST'])
@login_required
def review_funding_dept(id):
    if current_user.role != 'dept_coord':
        flash('You do not have permission to review funding requests', 'error')
        return redirect(url_for('dashboard'))
    
    funding = FundingRequest.query.get_or_404(id)
    application = funding.ssip_application
    
    if request.method == 'POST':
        action = request.form.get('action')
        remarks = request.form.get('remarks')
        
        if action == 'approve':
            funding.dept_status = 'approved'
        elif action == 'reject':
            funding.dept_status = 'rejected'
        
        funding.dept_remarks = remarks
        funding.dept_review_date = datetime.now()
        
        # Create notification
        create_notification(
            application=application,
            user=application.applicant,
            message=f'Your funding request for application {application.application_number} has been {action}d by department coordinator',
            type='success' if action == 'approve' else 'error'
        )
        
        db.session.commit()
        flash(f'Funding request has been {action}d', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('review_funding.html',
                         application=application,
                         funding=funding,
                         can_review=True)

@app.route('/funding/<int:id>/college/review', methods=['GET', 'POST'])
@login_required
def review_funding_college(id):
    if current_user.role != 'college_coord':
        flash('You do not have permission to review funding requests', 'error')
        return redirect(url_for('dashboard'))
    
    funding = FundingRequest.query.get_or_404(id)
    application = funding.ssip_application
    
    # Check if department has approved
    if funding.dept_status != 'approved':
        flash('Department approval is required first', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        remarks = request.form.get('remarks')
        
        if action == 'approve':
            funding.college_status = 'approved'
        elif action == 'reject':
            funding.college_status = 'rejected'
        
        funding.college_remarks = remarks
        funding.college_review_date = datetime.now()
        
        # Create notification
        create_notification(
            application=application,
            user=application.applicant,
            message=f'Your funding request for application {application.application_number} has been {action}d by college coordinator',
            type='success' if action == 'approve' else 'error'
        )
        
        db.session.commit()
        flash(f'Funding request has been {action}d', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('review_funding.html',
                         application=application,
                         funding=funding,
                         can_review=True)

@app.route('/funding/<int:id>/principal/review', methods=['GET', 'POST'])
@login_required
def review_funding_principal(id):
    if current_user.role != 'principal':
        flash('You do not have permission to review funding requests', 'error')
        return redirect(url_for('dashboard'))
    
    funding = FundingRequest.query.get_or_404(id)
    application = funding.ssip_application
    
    # Check if department and college have approved
    if funding.dept_status != 'approved' or funding.college_status != 'approved':
        flash('Both department and college approval are required first', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        remarks = request.form.get('remarks')
        
        if action == 'approve':
            funding.principal_status = 'approved'
        elif action == 'reject':
            funding.principal_status = 'rejected'
        
        funding.principal_remarks = remarks
        funding.principal_review_date = datetime.now()
        
        # Create notification
        create_notification(
            application=application,
            user=application.applicant,
            message=f'Your funding request for application {application.application_number} has been {action}d by principal',
            type='success' if action == 'approve' else 'error'
        )
        
        db.session.commit()
        flash(f'Funding request has been {action}d', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('review_funding.html',
                         application=application,
                         funding=funding,
                         can_review=True)

@app.route('/application/<int:id>/dept/review', methods=['GET', 'POST'])
@login_required
def review_application_dept(id):
    if current_user.role != 'dept_coord':
        flash('You do not have permission to review applications', 'error')
        return redirect(url_for('dashboard'))
    
    application = Application.query.get_or_404(id)
    
    if request.method == 'POST':
        action = request.form.get('action')
        remarks = request.form.get('remarks')
        
        if action == 'approve':
            application.dept_status = 'approved'
        elif action == 'reject':
            application.dept_status = 'rejected'
        
        application.dept_remarks = remarks
        application.dept_review_date = datetime.now()
        
        # Create notification
        create_notification(
            application=application,
            user=application.applicant,
            message=f'Your application {application.application_number} has been {action}d by department coordinator',
            type='success' if action == 'approve' else 'error'
        )
        
        db.session.commit()
        flash(f'Application has been {action}d', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('review_application.html',
                         application=application,
                         can_review=True)

@app.route('/application/<int:id>/college/review', methods=['GET', 'POST'])
@login_required
def review_application_college(id):
    if current_user.role != 'college_coord':
        flash('You do not have permission to review applications', 'error')
        return redirect(url_for('dashboard'))
    
    application = Application.query.get_or_404(id)
    
    # Check if department has approved
    if application.dept_status != 'approved':
        flash('Department approval is required first', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        remarks = request.form.get('remarks')
        
        if action == 'approve':
            application.college_status = 'approved'
        elif action == 'reject':
            application.college_status = 'rejected'
        
        application.college_remarks = remarks
        application.college_review_date = datetime.now()
        
        # Create notification
        create_notification(
            application=application,
            user=application.applicant,
            message=f'Your application {application.application_number} has been {action}d by college coordinator',
            type='success' if action == 'approve' else 'error'
        )
        
        db.session.commit()
        flash(f'Application has been {action}d', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('review_application.html',
                         application=application,
                         can_review=True)

@app.route('/application/<int:id>/principal/review', methods=['GET', 'POST'])
@login_required
def review_application_principal(id):
    if current_user.role != 'principal':
        flash('You do not have permission to review applications', 'error')
        return redirect(url_for('dashboard'))
    
    application = Application.query.get_or_404(id)
    
    # Check if department and college have approved
    if application.dept_status != 'approved' or application.college_status != 'approved':
        flash('Both department and college approval are required first', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        remarks = request.form.get('remarks')
        
        if action == 'approve':
            application.principal_status = 'approved'
        elif action == 'reject':
            application.principal_status = 'rejected'
        
        application.principal_remarks = remarks
        application.principal_review_date = datetime.now()
        
        # Create notification
        create_notification(
            application=application,
            user=application.applicant,
            message=f'Your application {application.application_number} has been {action}d by principal',
            type='success' if action == 'approve' else 'error'
        )
        
        db.session.commit()
        flash(f'Application has been {action}d', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('review_application.html',
                         application=application,
                         can_review=True)

@app.route('/application/<int:application_id>/funding/create', methods=['GET', 'POST'])
@login_required
def create_funding_request(application_id):
    if current_user.role != 'student':
        flash('Only students can create funding requests', 'error')
        return redirect(url_for('dashboard'))
    
    application = Application.query.get_or_404(application_id)
    
    # Check if application belongs to current user
    if application.user_id != current_user.id:
        flash('You can only create funding requests for your own applications', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if application is fully approved
    if not (application.dept_status == 'approved' and 
            application.college_status == 'approved' and 
            application.principal_status == 'approved'):
        flash('Application must be fully approved before requesting funding', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if funding request already exists
    if application.funding_request:
        flash('A funding request already exists for this application', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        actual_cost = float(request.form.get('actual_cost'))
        remarks = request.form.get('remarks')
        bill = request.files.get('bill')
        
        if bill:
            filename = secure_filename(bill.filename)
            bill_path = os.path.join('uploads', 'bills', filename)
            bill.save(os.path.join(app.root_path, 'static', bill_path))
        else:
            bill_path = None
        
        funding_request = FundingRequest(
            application_id=application.id,
            actual_cost=actual_cost,
            remarks=remarks,
            bill_path=bill_path,
            dept_status='pending',
            college_status='pending',
            principal_status='pending'
        )
        
        db.session.add(funding_request)
        db.session.commit()
        
        flash('Funding request created successfully', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('funding_request.html', application=application)

@app.route('/application/<int:application_id>/delete', methods=['POST'])
@login_required
def delete_application(application_id):
    application = Application.query.get_or_404(application_id)
    
    # Check if the application belongs to the current user
    if application.user_id != current_user.id:
        flash('You can only delete your own applications', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if application has any funding requests
    if application.funding_request:
        flash('Cannot delete application with existing funding request', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        # First delete all notifications related to this application
        Notification.query.filter_by(application_id=application.id).delete()
        
        # Then delete the application
        db.session.delete(application)
        db.session.commit()
        
        flash('Application deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting application. Please try again.', 'error')
        print(f"Error: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/application/<int:application_id>/update', methods=['GET', 'POST'])
@login_required
def update_application(application_id):
    application = Application.query.get_or_404(application_id)
    
    # Check if the application belongs to the current user
    if application.user_id != current_user.id:
        flash('You can only update your own applications', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if application is rejected
    if not (application.dept_status == 'rejected' or 
            application.college_status == 'rejected' or 
            application.principal_status == 'rejected'):
        flash('Only rejected applications can be updated', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if application has any funding requests
    if application.funding_request:
        flash('Cannot update application with existing funding request', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Reset all approval statuses
        application.dept_status = 'pending'
        application.dept_remarks = None
        application.dept_review_date = None
        
        application.college_status = 'pending'
        application.college_remarks = None
        application.college_review_date = None
        
        application.principal_status = 'pending'
        application.principal_remarks = None
        application.principal_review_date = None
        
        # Update application details
        application.project_title = request.form.get('project_title')
        application.problem_statement = request.form.get('problem_statement')
        application.solution = request.form.get('solution')
        application.team_members = request.form.get('team_members')
        application.total_cost = float(request.form.get('total_cost'))
        
        # Handle quotation file
        if 'quotation' in request.files:
            quotation = request.files['quotation']
            if quotation.filename:
                filename = secure_filename(quotation.filename)
                quotation_path = os.path.join('uploads', 'quotations', filename)
                quotation.save(os.path.join(app.root_path, 'static', quotation_path))
                application.quotation_path = quotation_path

        try:
            db.session.commit()
            
            # Create notification for department coordinator
            dept_coord = User.query.filter_by(role='dept_coord').first()
            if dept_coord:
                notification = Notification(
                    user_id=dept_coord.id,
                    application_id=application.id,
                    message=f'Updated SSIP application ({application.application_number}) requires review',
                    type='application_update'
                )
                db.session.add(notification)
                db.session.commit()
            
            flash('Application updated successfully', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating application. Please try again.', 'error')
            print(f"Error: {str(e)}")
            return redirect(url_for('dashboard'))

    return render_template('update_application.html', application=application)

@app.route('/chatbot', methods=['POST'])
@login_required
def chatbot():
    try:
        data = request.get_json()
        if not data or 'message' not in data:
            return jsonify({'response': 'Invalid request. Please try again.'}), 400
            
        user_message = data['message'].lower().strip()
        
        # Simple responses
        if 'what' in user_message and 'ssip' in user_message:
            return jsonify({'response': 'SSIP (Student Startup and Innovation Policy) is a Gujarat government initiative that supports innovative student projects with funding up to ₹2,00,000. It helps students develop entrepreneurship skills and turn their ideas into reality.'})
            
        if 'how' in user_message or 'apply' in user_message:
            return jsonify({'response': 'To apply for SSIP:\n1. Log in to your account\n2. Click "Submit New Application"\n3. Fill in your project details\n4. Upload required documents\n5. Submit for review'})
            
        if 'fund' in user_message or 'money' in user_message:
            return jsonify({'response': 'SSIP provides funding up to ₹2,00,000 for approved projects. The amount depends on your project requirements and evaluation.'})
            
        # Default response
        return jsonify({'response': 'I can help you with SSIP applications, funding, and processes. Try asking:\n- What is SSIP?\n- How to apply?\n- About funding\n- Required documents'})

    except Exception as e:
        print(f"Chatbot error: {str(e)}")
        return jsonify({'response': 'Sorry, I encountered an error. Please try again.'}), 500

@app.template_filter('datetime')
def format_datetime(value):
    if value is None:
        return ""
    return value.strftime('%B %d, %Y %I:%M %p')

@app.template_filter('from_json')
def from_json(value):
    try:
        return json.loads(value) if value else []
    except:
        return []

if __name__ == '__main__':
    # Create upload directories if they don't exist
    os.makedirs(os.path.join('uploads', 'quotations'), exist_ok=True)
    os.makedirs(os.path.join('uploads', 'bills'), exist_ok=True)
    
    with app.app_context():
        db.create_all()
    app.run(debug=True)

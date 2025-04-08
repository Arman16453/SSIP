from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from itsdangerous import URLSafeTimedSerializer
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime
import os
import json
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ssip.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-password'

# Initialize serializer for secure tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

@app.template_filter('from_json')
def from_json(value):
    try:
        return json.loads(value) if value else []
    except:
        return []

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # student, dept_coord, college_coord, principal
    name = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100))
    applications = db.relationship('Application', backref='applicant', lazy=True)

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    application_number = db.Column(db.String(20), unique=True, nullable=False)
    project_title = db.Column(db.String(200), nullable=False)
    problem_statement = db.Column(db.Text, nullable=False)
    solution = db.Column(db.Text, nullable=False)
    team_members = db.Column(db.Text, nullable=False)
    required_components = db.Column(db.Text, nullable=False)
    total_cost = db.Column(db.Float, nullable=False)
    mentor_name = db.Column(db.String(100), nullable=True)
    mentor_email = db.Column(db.String(120), nullable=True)
    mentor_approval = db.Column(db.Boolean, default=False)
    mentor_approval_date = db.Column(db.DateTime, nullable=True)
    dept_status = db.Column(db.String(20), default='pending')
    dept_remarks = db.Column(db.Text)
    dept_review_date = db.Column(db.DateTime)
    college_status = db.Column(db.String(20), default='pending')
    college_remarks = db.Column(db.Text)
    college_review_date = db.Column(db.DateTime)
    principal_status = db.Column(db.String(20), default='pending')
    principal_remarks = db.Column(db.Text)
    principal_review_date = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    purchase_lists = db.relationship('PurchaseList', backref='application', lazy=True)
    utilization_certificates = db.relationship('UtilizationCertificate', backref='application', lazy=True)
    notifications = db.relationship('Notification', backref=db.backref('application', lazy=True), lazy=True)

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

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey('application.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), nullable=False)  # 'approval', 'rejection', 'comment'
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('notifications', lazy=True), lazy=True)

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
        # Show student's applications
        applications = Application.query.filter_by(user_id=current_user.id).all()
        purchase_items = []
        utilization_certificates = []  # Initialize empty list for students
        for app in applications:
            if app.principal_status == 'approved':
                items = PurchaseList.query.filter_by(application_id=app.id).all()
                purchase_items.extend(items)
        approved_applications = []
    elif current_user.role == 'dept_coord':
        # Show only pending applications
        applications = Application.query.filter_by(dept_status='pending').all()
        
        # Get pending purchase items
        purchase_items = PurchaseList.query.join(Application).filter(
            PurchaseList.dept_status == 'pending',
            Application.principal_status == 'approved'
        ).all()
        
        # Get pending utilization certificates
        utilization_certificates = UtilizationCertificate.query.join(Application).filter(
            UtilizationCertificate.dept_status == 'pending',
            Application.principal_status == 'approved'
        ).all()
        
        # Get applications history (both approved and rejected)
        approved_applications = Application.query.filter(
            Application.dept_status.in_(['approved', 'rejected'])
        ).order_by(Application.created_at.desc()).all()
    elif current_user.role == 'college_coord':
        # Show pending applications
        applications = Application.query.filter_by(dept_status='approved', college_status='pending').all()
        
        # Get pending purchase items
        purchase_items = PurchaseList.query.join(Application).filter(
            PurchaseList.dept_status == 'approved',
            PurchaseList.college_status == 'pending',
            Application.principal_status == 'approved'
        ).all()
        
        # Get pending utilization certificates
        utilization_certificates = UtilizationCertificate.query.join(Application).filter(
            UtilizationCertificate.dept_status == 'approved',
            UtilizationCertificate.college_status == 'pending',
            Application.principal_status == 'approved'
        ).all()
        
        # Get applications history (both approved and rejected)
        approved_applications = Application.query.filter(
            Application.dept_status == 'approved',
            Application.college_status.in_(['approved', 'rejected'])
        ).order_by(Application.created_at.desc()).all()
    else:  # principal
        # Show pending applications
        applications = Application.query.filter_by(college_status='approved', principal_status='pending').all()
        
        # Get pending purchase items
        purchase_items = PurchaseList.query.join(Application).filter(
            PurchaseList.dept_status == 'approved',
            PurchaseList.college_status == 'approved',
            PurchaseList.principal_status == 'pending',
            Application.principal_status == 'approved'
        ).all()
        
        # Get pending utilization certificates
        utilization_certificates = UtilizationCertificate.query.join(Application).filter(
            UtilizationCertificate.dept_status == 'approved',
            UtilizationCertificate.college_status == 'approved',
            UtilizationCertificate.principal_status == 'pending',
            Application.principal_status == 'approved'
        ).all()
        
        # Get applications history (both approved and rejected)
        approved_applications = Application.query.filter(
            Application.dept_status == 'approved',
            Application.college_status == 'approved',
            Application.principal_status.in_(['approved', 'rejected'])
        ).order_by(Application.created_at.desc()).all()
    
    return render_template('dashboard.html', 
                         applications=applications,
                         purchase_items=purchase_items,
                         utilization_certificates=utilization_certificates,
                         approved_applications=approved_applications)

@app.route('/application/new', methods=['GET', 'POST'])
@login_required
def new_application():
    if current_user.role != 'student':
        flash('Only students can create applications', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            # Process team members
            team_members = request.form.getlist('team_members[]')
            team_members_json = json.dumps(list(filter(None, team_members)))  # Filter out empty values
            
            # Process components and costs
            components = []
            application = Application(
                application_number=application_number,
                project_title=request.form.get('project_title'),
                problem_statement=request.form.get('problem_statement'),
                solution=request.form.get('solution'),
                team_members=json.dumps(request.form.getlist('team_member[]')),
                required_components=json.dumps(request.form.getlist('component[]')),
                total_cost=float(request.form.get('total_cost')),
                mentor_name=request.form.get('mentor_name'),
                mentor_email=request.form.get('mentor_email'),
                user_id=current_user.id
            )
            
            db.session.add(application)
            db.session.commit()
            
            def create_notification(application, user, message, type='info'):
                notification = Notification(
                    application_id=application.id,
                    user_id=user.id,
                    message=message,
                    type=type
                )
                db.session.add(notification)
                db.session.commit()

            def send_email(subject, recipient, body):
                msg = Message(subject,
                              sender=app.config['MAIL_USERNAME'],
                              recipients=[recipient])
                msg.body = body
                mail.send(msg)

            def notify_status_change(application, status, remarks=None, level='dept'):
                # Get the relevant coordinator based on level
                if level == 'dept':
                    coordinator = User.query.filter_by(role='dept_coord', department=application.applicant.department).first()
                elif level == 'college':
                    coordinator = User.query.filter_by(role='college_coord').first()
                else:  # principal
                    coordinator = User.query.filter_by(role='principal').first()
                
                # Create notification for student
                student_msg = f'Your application {application.application_number} has been {status} by {level} coordinator'
                if remarks:
                    student_msg += f'\nRemarks: {remarks}'
                create_notification(application, application.applicant, student_msg, type=status)
                
                # Send email to student
                send_email(
                    f'Application {status.title()} by {level.title()} Coordinator',
                    application.applicant.email,
                    student_msg
                )
                
                # If mentor exists and application is newly submitted
                if application.mentor_email and status == 'pending':
                    mentor_msg = f'New application {application.application_number} requires your approval'
                    send_email(
                        'New Application Requires Approval',
                        application.mentor_email,
                        mentor_msg
                    )
                
                # Generate mentor approval token
                token = serializer.dumps(application.mentor_email, salt='mentor-approval')
                approval_url = url_for('mentor_approve_application', id=application.id, token=token, _external=True)
                
                # Send email to mentor
                send_email(
                    'SSIP Application Requires Your Approval',
                    application.mentor_email,
                    f'Dear {application.mentor_name},\n\n'
                    f'A new SSIP application ({application.application_number}) has been submitted by {current_user.name} '
                    f'and requires your approval.\n\n'
                    f'Please click the following link to review and approve/reject the application:\n'
                    f'{approval_url}\n\n'
                    f'This link will expire in 7 days.'
                )
                
                flash('Application submitted successfully. Mentor will be notified for approval.', 'success')
                return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Error submitting application: ' + str(e), 'danger')
            return redirect(url_for('new_application'))
    
    return render_template('new_application.html')

@app.route('/application/<int:id>')
@login_required
def view_application(id):
    application = Application.query.get_or_404(id)
    return render_template('view_application.html', application=application)

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

@app.route('/application/<int:id>/dept/reject', methods=['POST'])
@login_required
def reject_dept(id):
    if current_user.role != 'dept_coord':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    application = Application.query.get_or_404(id)
    reason = request.form.get('reason')
    if not reason:
        flash('Rejection reason is required', 'danger')
        return redirect(url_for('view_application', id=id))
    
    application.dept_status = 'rejected'
    application.dept_remarks = reason
    application.dept_review_date = datetime.utcnow()
    
    # Notify student
    student_msg = f'Your application {application.application_number} has been rejected by department coordinator\nReason: {reason}'
    create_notification(application, application.applicant, student_msg, type='rejection')
    send_email('Application Rejected', application.applicant.email, student_msg)
    
    db.session.commit()
    flash('Application rejected successfully', 'success')
    return redirect(url_for('dashboard'))

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

@app.route('/application/<int:id>/college/reject', methods=['POST'])
@login_required
def reject_college(id):
    if current_user.role != 'college_coord':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    application = Application.query.get_or_404(id)
    reason = request.form.get('reason')
    if not reason:
        flash('Rejection reason is required', 'danger')
        return redirect(url_for('view_application', id=id))
    
    application.college_status = 'rejected'
    application.college_remarks = reason
    application.college_review_date = datetime.utcnow()
    
    # Notify student
    student_msg = f'Your application {application.application_number} has been rejected by college coordinator\nReason: {reason}'
    create_notification(application, application.applicant, student_msg, type='rejection')
    send_email('Application Rejected', application.applicant.email, student_msg)
    
    db.session.commit()
    flash('Application rejected successfully', 'success')
    return redirect(url_for('dashboard'))

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

@app.route('/application/<int:id>/principal/reject', methods=['POST'])
@login_required
def reject_principal(id):
    if current_user.role != 'principal':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    application = Application.query.get_or_404(id)
    reason = request.form.get('reason')
    if not reason:
        flash('Rejection reason is required', 'danger')
        return redirect(url_for('view_application', id=id))
    
    application.principal_status = 'rejected'
    application.principal_remarks = reason
    application.principal_review_date = datetime.utcnow()
    
    # Notify student
    student_msg = f'Your application {application.application_number} has been rejected by principal\nReason: {reason}'
    create_notification(application, application.applicant, student_msg, type='rejection')
    send_email('Application Rejected', application.applicant.email, student_msg)
    
    db.session.commit()
    flash('Application rejected successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/application/<int:id>/reject', methods=['POST'])
@login_required
def reject_application(id):
    if current_user.role not in ['dept_coord', 'college_coord', 'principal']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    application = Application.query.get_or_404(id)
    remarks = request.form.get('remarks')
    
    if not remarks:
        flash('Remarks are required for rejection', 'danger')
        return redirect(url_for('dashboard'))
    
    # Department coordinator rejection
    if current_user.role == 'dept_coord':
        if not application.mentor_approval:
            flash('Application must be approved by mentor first', 'danger')
            return redirect(url_for('dashboard'))
        
        application.dept_status = 'rejected'
        application.dept_remarks = remarks
        application.dept_review_date = datetime.utcnow()
        
        # Notify student
        create_notification(
            application,
            application.applicant,
            f'Your application has been rejected by department coordinator.\nRemarks: {remarks}',
            type='rejection'
        )
    
    # College coordinator rejection
    elif current_user.role == 'college_coord':
        application.college_status = 'rejected'
        application.college_remarks = remarks
        application.college_review_date = datetime.utcnow()
        
        # Notify student
        create_notification(
            application,
            application.applicant,
            f'Your application has been rejected by college coordinator.\nRemarks: {remarks}',
            type='rejection'
        )
    
    # Principal rejection
    elif current_user.role == 'principal':
        application.principal_status = 'rejected'
        application.principal_remarks = remarks
        application.principal_review_date = datetime.utcnow()
        
        # Notify student
        create_notification(
            application,
            application.applicant,
            f'Your application has been rejected by principal.\nRemarks: {remarks}',
            type='rejection'
        )
    
    db.session.commit()
    flash('Application rejected', 'danger')
    return redirect(url_for('dashboard'))

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

if __name__ == '__main__':
    # Create upload directories if they don't exist
    os.makedirs(os.path.join('uploads', 'quotations'), exist_ok=True)
    os.makedirs(os.path.join('uploads', 'bills'), exist_ok=True)
    
    with app.app_context():
        db.create_all()
    app.run(debug=True)

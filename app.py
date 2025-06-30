from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import date
import random
import time
from flask_mail import Mail, Message
from urllib.parse import quote_plus 
from fpdf import FPDF
from datetime import datetime
from flask import make_response, Response 
from fpdf.enums import XPos, YPos
from sqlalchemy import func

# --- APP CONFIGURATION ---
app = Flask(__name__)
app.secret_key = 'your_super_secret_key_12345'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///attendance_system.db'      # This is for SQLite 
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@Attendance_logg258@localhost/attendance_system'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- FLASK-MAIL CONFIGURATION (EXAMPLE FOR GMAIL) ---
# IMPORTANT: For Gmail, we might need to "Allow less secure app access"
# In my Google account settings OR generate an "App Password".
# It's better to use an App Password for security.
# DO NOT hardcode your real password in production. Use environment variables.

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587  # Or 465 if using SSL
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False # True if using port 465
app.config['MAIL_USERNAME'] = 'loggerattendance@gmail.com'  # Gmail address
app.config['MAIL_PASSWORD'] = 'tcgj qswm ewvm eoju' # Your Gmail App Password or regular password (less secure)
app.config['MAIL_DEFAULT_SENDER'] = ('Attendance Logger', 'loggerattendance@gmail.com') # Tuple: (Display Name, Email Address)


# --- NEW MYSQL CONFIGURATION ---

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)


# OTP expiry = 5 minutes
OTP_EXPIRY_SECONDS = 300

# --- CACHE PREVENTION ---


# --- DATABASE MODELS ---
# What is the use of database models ?


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    students = db.relationship('Student', backref='creator', lazy=True)
    attendance_records = db.relationship('AttendanceRecord', backref='marker', lazy=True) 
    
    def __repr__(self):
        return f"User('{self.email}')"

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(20), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    semester = db.Column(db.Integer, nullable=False)
    email = db.Column(db.String(120), nullable=False)
    fathers_name = db.Column(db.String(100), nullable=False)
    mothers_name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    city = db.Column(db.String(50), nullable=False)
    state = db.Column(db.String(50), nullable=False)
    pin_code = db.Column(db.String(6), nullable=False)
    attendance_records = db.relationship('AttendanceRecord', backref='student', lazy=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'student_id', name='uq_user_student_id'),
        db.UniqueConstraint('user_id', 'email', name='uq_user_student_email'),
    )
    
    def __repr__(self):
        return f"Student('{self.first_name} {self.last_name}', '{self.student_id}')"

class AttendanceRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False, default=date.today)
    status = db.Column(db.String(10), nullable=False)
    student_id_ref = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    marked_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def __repr__(self):
        return f"AttendanceRecord('{self.student.first_name}', '{self.date}', '{self.status}')"




# ================================    CORE PUBLIC ROUTES    ===================================

@app.route('/')
def home():
    return render_template('intro.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if User.query.filter_by(email=email).first():
            flash('That email is already registered. Please log in.', 'warning')
            return redirect(url_for('login'))
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        # Create and saves new user
        new_user = User(email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)    # Logs out the user by removing user_id from session.
    flash('You have been successfully logged out.', 'info')
    return redirect(url_for('login'))


# =============================      PROTECTED DASHBOARD ROUTES     ==========================

# Replace your old /dashboard function with this corrected one

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    user = db.session.get(User, user_id)
    user_email = user.email if user else 'N/A'
    
    total_students = Student.query.filter_by(user_id=user_id).count()
    
    today = date.today()

    # It counts the number of DISTINCT student IDs that have a 'Present' record for today.
    # This prevents counting the same student multiple times.
    present_today = db.session.query(func.count(func.distinct(AttendanceRecord.student_id_ref))).filter(
        AttendanceRecord.marked_by_user_id == user_id,
        AttendanceRecord.date == today,
        AttendanceRecord.status == 'Present'
    ).scalar()

    student_list = Student.query.filter_by(user_id=user_id).order_by(Student.first_name).all()

    return render_template(
        'dashboard.html',
        user_email=user_email,
        total_students=total_students,
        present_today=present_today,
        student_list=student_list
    )



#   ===============    This is for Student Registration Route   ======================   

@app.route('/registration')
def registration():
    # login protection
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    return render_template('registration.html')

# This route accepts only POST requests.
# Used to submit the student registration form.
# The form must include fields like name, roll number, etc.
# This add_student is in registration.html page
@app.route('/add_student', methods=['POST'])  
def add_student():
    if 'user_id' not in session: 
        return redirect(url_for('login'))
    

    # Gets the currently logged-in user’s ID from the session.
    # Gets the student_id and email fields from the form input.
    current_user_id = session['user_id']
    student_id_form = request.form.get('student_id')
    email_form = request.form.get('email')


    # If a student with the same roll number already exists for this user, stop and show an error.
    if Student.query.filter_by(student_id=student_id_form, user_id=current_user_id).first():
        flash(f'A student with Roll Number "{student_id_form}" already exists under your account.', 'danger')
        return redirect(url_for('registration'))
    
    # Similarly, stop if a student with the same email already exists.
    if Student.query.filter_by(email=email_form, user_id=current_user_id).first():
        flash(f'A student with the email "{email_form}" already exists under your account.', 'danger')
        return redirect(url_for('registration'))

    # Creates a new Student object using the submitted form fields.
    # It is linked to the logged-in user via user_id.
    new_student = Student(
        student_id=student_id_form, 
        email=email_form,
        first_name=request.form.get('first_name'), 
        last_name=request.form.get('last_name'),
        semester=request.form.get('semester'), 
        fathers_name=request.form.get('fathers_name'),
        mothers_name=request.form.get('mothers_name'), 
        address=request.form.get('address'),
        city=request.form.get('city'), 
        state=request.form.get('state'),
        pin_code=request.form.get('pin_code'),
        user_id=current_user_id
    )
    # Adds the new student record to the database and saves it.
    db.session.add(new_student)
    db.session.commit()
    flash('Student registered successfully!', 'success')
    return redirect(url_for('registration'))



#  =============================  This is for Student Update Route   ============================


@app.route('/userupdate', methods=['GET', 'POST'])
def userupdate():
    # 1. Protect the route
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    # This handles the "Show Information" button submission
    if request.method == 'POST':
        roll_number = request.form.get('roll_number_search')
        if not roll_number:
            flash('Please enter a roll number to search.', 'warning')
            return redirect(url_for('userupdate'))

        # Find the student belonging to the logged-in user
        student = Student.query.filter_by(
            student_id=roll_number,
            user_id=session['user_id']
        ).first()

        if not student:
            flash(f'No student found with Roll Number "{roll_number}".', 'danger')
            return redirect(url_for('userupdate'))

        # Re-render the same page, but now pass the found student object
        return render_template('user_update.html', student=student)

    # For a GET request, just show the initial page with the search box
    return render_template('user_update.html', student=None)


@app.route('/update_student_info', methods=['POST'])
def update_student_info():
    # 1. Protect the route
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    student_id = request.form.get('student_id_to_update')
    if not student_id:
        flash('An error occurred. Could not find student to update.', 'danger')
        return redirect(url_for('userupdate'))

    # Find the student to ensure they exist and belong to the current user
    student_to_update = db.session.get(Student, student_id)

    # Security Check: a user cannot update a student that is not theirs
    if not student_to_update or student_to_update.user_id != session['user_id']:
        flash('You do not have permission to update this student.', 'danger')
        return redirect(url_for('userupdate'))

    # 2. Update the student's record with the new data from the form
    student_to_update.fathers_name = request.form.get('fathers_name')
    student_to_update.mothers_name = request.form.get('mothers_name')
    student_to_update.address = request.form.get('address')
    student_to_update.city = request.form.get('city')
    student_to_update.state = request.form.get('state')
    student_to_update.pin_code = request.form.get('pin_code')

    # 3. Commit the changes to the database
    db.session.commit()

    flash('Student information updated successfully!', 'success')
    # 4. Redirect back to the clean update page
    return redirect(url_for('userupdate'))


#   =============================  This is for Attendance Marking Route  ==========================


@app.route('/attendancemarking', methods=['GET', 'POST'])
def attendancemarking():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    
    if request.method == 'POST':
        selected_semester = request.form.get('semester')
        if not selected_semester:
            flash('Please select a semester.', 'warning')
            return redirect(url_for('attendancemarking'))
            
        today = date.today()
        
        # --- THIS IS THE LOGIC ---
        
        # 1. First, get a list of all student IDs for whom attendance HAS been marked today.
        # We use a subquery for efficiency. This creates a temporary list in the database.
        marked_student_ids_subquery = db.session.query(AttendanceRecord.student_id_ref).filter(
            AttendanceRecord.marked_by_user_id == user_id,
            AttendanceRecord.date == today
        ).subquery()

        # 2. Now, fetch all students in the selected semester whose IDs are NOT IN the list from step 1.
        # This gives us a list of only the students who still need their attendance marked.
        unmarked_students = Student.query.filter(
            Student.user_id == user_id,
            Student.semester == selected_semester,
            Student.id.notin_(marked_student_ids_subquery)
        ).order_by(Student.first_name).all()

        # 3. Check if the list of unmarked students is empty.
        # If it's empty, it means everyone has been marked.
        if not unmarked_students:
            flash(f'Attendance for all students in Semester {selected_semester} has already been marked today.', 'info')
            return redirect(url_for('attendancemarking'))
            
        # --- END OF CORRECTED LOGIC ---

        # 4. If we are here, it means there are students to be marked.
        # We pass this list of UNMARKED students to the template.
        return render_template(
            'atten_marking.html', 
            students=unmarked_students, 
            selected_semester=selected_semester,
            today_date=today.strftime('%B %d, %Y')
        )

    # For a GET request, just show the initial page
    return render_template('atten_marking.html', students=None, selected_semester=None)




@app.route('/submit_attendance', methods=['POST'])
def submit_attendance():
    # 1. Protect the route
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    today = date.today()
    
    # 2. Loop through the submitted form data
    # The form data will be like: {'status_1': 'Present', 'status_2': 'Absent', ...}
    for key, status in request.form.items():
        if key.startswith('status_'):
            # Extract the student_id from the key (e.g., 'status_1' -> '1')
            student_id = key.split('_')[1]
            
            # Create a new attendance record
            new_record = AttendanceRecord(
                date=today,
                status=status,
                student_id_ref=student_id,
                marked_by_user_id=user_id
            )
            db.session.add(new_record)
    
    # 3. Commit all the new records to the database at once
    try:
        db.session.commit()
        flash('Attendance submitted successfully!', 'success')
    except Exception as e:
        db.session.rollback() # Rollback changes if an error occurs
        flash(f'An error occurred while submitting attendance: {e}', 'danger')

    # 4. Redirect back to the clean attendance marking page
    return redirect(url_for('attendancemarking'))




#  =============================  This is for attendance report   ============================


#    ==== Copied from AI ======
# --- ATTENDANCE REPORT FLOW ---

@app.route('/attendancereport', methods=['GET', 'POST'])
def attendancereport():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    active_tab = request.args.get('tab', 'roll') # Default to 'roll' tab
    records = None
    report_title = ""

    if request.method == 'POST':
        report_type = request.form.get('report_type')
        query = AttendanceRecord.query.join(Student).filter(AttendanceRecord.marked_by_user_id == user_id)
        
        # Store query in session for PDF download
        session['last_report_query'] = {'type': report_type, 'form': request.form.to_dict()}
        active_tab = report_type # Make the submitted form's tab active
        
        # --- Build Query Based on Form ---
        if report_type == 'roll':
            roll_number = request.form.get('roll_number')
            query = query.filter(Student.student_id == roll_number)
            report_title = f"Report for Roll Number: {roll_number}"
        
        elif report_type == 'name':
            student_name = request.form.get('student_name')
            semester = request.form.get('semester')
            query = query.filter(Student.semester == semester, (Student.first_name + " " + Student.last_name).ilike(f'%{student_name}%'))
            report_title = f"Report for '{student_name}' in Semester {semester}"
            
        elif report_type == 'date':
            report_date_str = request.form.get('report_date')
            report_date = datetime.strptime(report_date_str, '%Y-%m-%d').date()
            query = query.filter(AttendanceRecord.date == report_date)
            report_title = f"Report for Date: {report_date.strftime('%d-%m-%Y')}"

        elif report_type == 'semester':
            semester = request.form.get('semester_only')
            query = query.filter(Student.semester == semester)
            report_title = f"Complete Report for Semester {semester}"
            
        records = query.order_by(AttendanceRecord.date.desc(), Student.student_id).all()
        
    return render_template('attendance_report.html', active_tab=active_tab, records=records, report_title=report_title)


# Replace your old PDF class with this one
class PDF(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 15)
        self.cell(0, 10, 'Attendance Report', align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', align='C')
        
    def chapter_title(self, title):
        self.set_font('Helvetica', 'B', 12)
        # Sanitize title for PDF
        safe_title = title.encode('latin-1', 'replace').decode('latin-1')
        self.cell(0, 10, safe_title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(5)
        
    def table_header(self):
        self.set_font('Helvetica', 'B', 10)
        self.cell(30, 10, 'Date', border=1)
        self.cell(40, 10, 'Roll Number', border=1)
        self.cell(80, 10, 'Student Name', border=1)
        self.cell(30, 10, 'Status', border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
    def table_row(self, data):
        self.set_font('Helvetica', '', 10)
        self.cell(30, 10, data[0], border=1)
        self.cell(40, 10, data[1], border=1)
        self.cell(80, 10, data[2], border=1)
        self.cell(30, 10, data[3], border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)




@app.route('/download_report_pdf')
def download_report_pdf():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    last_query_data = session.get('last_report_query')
    if not last_query_data:
        flash('No report has been generated yet. Please generate a report first.', 'warning')
        return redirect(url_for('attendancereport'))

    # Re-run the query using the saved criteria
    user_id = session['user_id']
    report_type = last_query_data['type']
    form_data = last_query_data['form']
    query = AttendanceRecord.query.join(Student).filter(AttendanceRecord.marked_by_user_id == user_id)
    report_title = "Attendance Report"

    if report_type == 'roll':
        roll_number = form_data.get('roll_number')
        query = query.filter(Student.student_id == roll_number)
        report_title = f"Report for Roll No: {roll_number}"
    elif report_type == 'name':
        student_name = form_data.get('student_name')
        semester = form_data.get('semester')
        query = query.filter(Student.semester == semester, (Student.first_name + " " + Student.last_name).ilike(f'%{student_name}%'))
        report_title = f"Report for '{student_name}' (Sem {semester})"
    elif report_type == 'date':
        report_date_str = form_data.get('report_date')
        report_date = datetime.strptime(report_date_str, '%Y-%m-%d').date()
        query = query.filter(AttendanceRecord.date == report_date)
        report_title = f"Report for Date: {report_date.strftime('%d-%m-%Y')}"
    elif report_type == 'semester':
        semester = form_data.get('semester_only')
        query = query.filter(Student.semester == semester)
        report_title = f"Report for Semester {semester}"

    records = query.order_by(AttendanceRecord.date.desc(), Student.student_id).all()

    # Generate PDF
    pdf = PDF()
    pdf.add_page()
    pdf.chapter_title(report_title)
    pdf.table_header()

    for record in records:
        student_name = f"{record.student.first_name} {record.student.last_name}"
        # Sanitize the name to be safe for the PDF's character set
        safe_name = student_name.encode('latin-1', 'replace').decode('latin-1')
        
        data = [
            record.date.strftime('%d-%m-%Y'),
            record.student.student_id,
            safe_name,
            record.status
        ]
        pdf.table_row(data)

    # We create a Response object directly from the PDF's byte output.
    # pdf_output = pdf.output()
    pdf_output = bytes(pdf.output())
    response = Response(pdf_output, mimetype='application/pdf')
    response.headers['Content-Disposition'] = 'attachment; filename=attendance_report.pdf'
    # -----------------------------------
    
    return response



#   =============================  This is for Contact Route   ===========================
@app.route('/contact')
def contact():
    return render_template('contact.html')


#   =============================  This is for Forget Password Route   ===========================

@app.route("/forget")
def forget():
    return render_template('forget_email.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Email not registered. Please check the email address and try again.', 'error')
            return redirect(url_for('forgot_password'))

        # Generate and store OTP in the session
        otp = str(random.randint(100000, 999999))
        session['otp_data'] = {
            'email': email,
            'otp': otp,
            'timestamp': time.time()
        }
        
        # --- Send OTP via Email ---
        try:
            msg_title = "Your Password Reset OTP"
            msg = Message(msg_title, recipients=[email])
            msg.body = f"Your One-Time Password (OTP) for resetting your password is: {otp}\n" \
                       f"This OTP is valid for {OTP_EXPIRY_SECONDS // 60} minutes.\n" \
                       f"If you did not request this, please ignore this email."
            
            mail.send(msg)
            app.logger.info(f"OTP email sent to {email}.")
            
            # Redirect to the OTP verification page
            return redirect(url_for('verify_otp'))
            
        except Exception as e:
            app.logger.error(f"Failed to send OTP email to {email}: {e}")
            flash('Failed to send OTP email. Please try again later or contact support.', 'error')
            return redirect(url_for('forgot_password'))

    # For GET request, just show the email entry form
    return render_template('forget_email.html')


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    otp_data = session.get('otp_data')
    
    # If there's no OTP data in session, redirect to the start
    if not otp_data:
        flash('Your session has expired or is invalid. Please start over.', 'warning')
        return redirect(url_for('forgot_password'))

    email = otp_data['email']

    if request.method == 'POST':
        submitted_otp = request.form.get('otp')
        
        # Check for OTP Expiry
        if (time.time() - otp_data.get('timestamp', 0)) > OTP_EXPIRY_SECONDS:
            session.pop('otp_data', None) # Clear expired OTP
            flash('OTP has expired. Please request a new one.', 'error')
            return redirect(url_for('forgot_password'))

        # Check if OTP is correct
        if otp_data.get('otp') == submitted_otp:
            # Mark OTP as verified in the session for the next step
            session['otp_verified'] = True
            return redirect(url_for('set_new_password'))
        else:
            flash('Invalid OTP. Please try again.', 'error')
            # Stay on the same page, but pass the email again to display it
            return render_template('verify_otp.html', email=email)

    # For GET request, show the verification form
    return render_template('verify_otp.html', email=email)


@app.route('/set-new-password', methods=['GET', 'POST'])
def set_new_password():
    # Security check: ensure user has verified OTP and hasn't just typed in the URL
    if not session.get('otp_verified'):
        flash('Please verify your OTP first.', 'warning')
        return redirect(url_for('forgot_password'))
        
    otp_data = session.get('otp_data')
    if not otp_data: # Double check in case session clears unexpectedly
        flash('Your session has expired. Please start over.', 'warning')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        
        # Basic password validation
        if not new_password or len(new_password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('set_new_password.html')

        email = otp_data['email']
        user = User.query.filter_by(email=email).first()

        if user:
            # Hash the new password and update the user record
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password = hashed_password
            db.session.commit()
            
            # Clear all session data related to the reset process
            session.pop('otp_data', None)
            session.pop('otp_verified', None)
            
            flash('Your password has been reset successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            # This case is unlikely but good to handle
            flash('An unexpected error occurred. User not found.', 'error')
            return redirect(url_for('forgot_password'))

    return render_template('set_new_password.html')


# --- APP STARTUP ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
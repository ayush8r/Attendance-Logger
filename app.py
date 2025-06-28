from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import date
import random
import time
from flask_mail import Mail, Message


# --- APP CONFIGURATION ---
app = Flask(__name__)
app.secret_key = 'your_super_secret_key_12345'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///attendance_system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)


OTP_EXPIRY_SECONDS = 300

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



# --- CACHE PREVENTION ---
@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# --- DATABASE MODELS ---

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


# --- CORE PUBLIC ROUTES ---

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
        new_user = User(email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    flash('You have been successfully logged out.', 'info')
    return redirect(url_for('login'))

# --- PROTECTED DASHBOARD ROUTES ---

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    
    user = User.query.get(user_id)
    user_email = user.email if user else 'N/A'
    
    total_students = Student.query.filter_by(user_id=user_id).count()
    
    today = date.today()
    present_today = AttendanceRecord.query.filter_by(
        marked_by_user_id=user_id,
        date=today,
        status='Present'
    ).count()

    student_list = Student.query.filter_by(user_id=user_id).order_by(Student.first_name).all()

    return render_template(
        'dashboard.html',
        user_email=user_email,
        total_students=total_students,
        present_today=present_today,
        student_list=student_list
    )

@app.route('/registration')
def registration():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    return render_template('registration.html')

@app.route('/add_student', methods=['POST'])
def add_student():
    if 'user_id' not in session: 
        return redirect(url_for('login'))
    
    current_user_id = session['user_id']
    student_id_form = request.form.get('student_id')
    email_form = request.form.get('email')

    if Student.query.filter_by(student_id=student_id_form, user_id=current_user_id).first():
        flash(f'A student with Roll Number "{student_id_form}" already exists under your account.', 'danger')
        return redirect(url_for('registration'))
    if Student.query.filter_by(email=email_form, user_id=current_user_id).first():
        flash(f'A student with the email "{email_form}" already exists under your account.', 'danger')
        return redirect(url_for('registration'))

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
    db.session.add(new_student)
    db.session.commit()
    flash('Student registered successfully!', 'success')
    return redirect(url_for('registration'))

@app.route('/attmarking')
def attmarking():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    return render_template('atten_marking.html')

@app.route('/userupdate')
def userupdate():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    return render_template('user_update.html')

@app.route('/report')
def report():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    return render_template('attendance_report.html')

@app.route("/contact")
def contact():
    return render_template("contact.html")

# --- API-LIKE ROUTES FOR JAVASCRIPT ---

@app.route('/get_students_by_semester/<int:semester_num>')
def get_students_by_semester(semester_num):
    if 'user_id' not in session: 
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_id_session = session['user_id']
    today = date.today()
    marked_today_subquery = db.session.query(AttendanceRecord.student_id_ref).filter(AttendanceRecord.date == today, AttendanceRecord.marked_by_user_id == user_id_session).subquery()
    students_to_mark = Student.query.filter(
        Student.semester == semester_num,
        Student.user_id == user_id_session,
        Student.id.notin_(marked_today_subquery)
    ).order_by(Student.student_id).all()

    if not students_to_mark:
        return jsonify({'error': 'All of your students in this semester have been marked for today or no students found for this semester.'}), 404
        
    student_data = [{'id': s.id, 'student_id': s.student_id, 'full_name': f"{s.first_name} {s.last_name}"} for s in students_to_mark]
    return jsonify(student_data)



@app.route('/submit_attendance', methods=['POST'])
def submit_attendance():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    user_id_session = session['user_id']
    today = date.today()
    for key, value in request.form.items():
        if key.startswith('status_'):
            student_id_ref = key.split('_')[1]
            record = AttendanceRecord(
                date=today,
                status=value,
                student_id_ref=student_id_ref,
                marked_by_user_id=user_id_session
            )
            db.session.add(record)
    db.session.commit()
    flash('Attendance submitted successfully!', 'success')
    return redirect(url_for('attmarking'))

@app.route('/get_student_info/<string:roll_number>')
def get_student_info(roll_number):
    if 'user_id' not in session: return jsonify({'error': 'Unauthorized'}), 401
    student = Student.query.filter_by(student_id=roll_number, user_id=session['user_id']).first()
    if student:
        return jsonify({ "fullName": f"{student.first_name} {student.last_name}", 
                        "rollNumber": student.student_id, 
                        "email": student.email, 
                        "semester": student.semester, 
                        "fathersName": student.fathers_name, 
                        "mothersName": student.mothers_name, 
                        "address": student.address, 
                        "city": student.city, 
                        "state": student.state, 
                        "pinCode": student.pin_code 
                        })
    return jsonify({'error': 'Student not found or you do not have permission to view them.'}), 404

@app.route('/update_student_info/<string:roll_number>', methods=['POST'])
def update_student_info(roll_number):
    if 'user_id' not in session: return jsonify({'error': 'Unauthorized'}), 401
    student = Student.query.filter_by(student_id=roll_number, user_id=session['user_id']).first()
    if not student: 
        return jsonify({'error': 'Student not found or you do not have permission to update them.'}), 404
    
    data = request.get_json()
    student.fathers_name = data.get('fathersName')
    student.mothers_name = data.get('mothersName')
    student.address = data.get('address')
    student.city = data.get('city')
    student.state = data.get('state')
    student.pin_code = data.get('pinCode')
    db.session.commit()
    return jsonify({'success': 'Student information updated successfully!'})


@app.route('/generate_report', methods=['POST'])
def generate_report():
    if 'user_id' not in session: 
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_id_session = session['user_id']
    records = []
    report_title = "Search Results"
    form_data = request.form

    try:
        base_query = AttendanceRecord.query.filter_by(marked_by_user_id=user_id_session)

        if form_data.get('roll_number'):
            roll = form_data.get('roll_number')
            student = Student.query.filter_by(student_id=roll, user_id=user_id_session).first()
            if student:
                records = base_query.filter_by(student_id_ref=student.id).order_by(AttendanceRecord.date.desc()).all()
                report_title = f"Report for {student.first_name} {student.last_name} (Roll: {student.student_id})"
            else: 
                return jsonify({'error': f"Student with Roll Number '{roll}' not found under your account."}), 404

        elif form_data.get('student_name') and form_data.get('semester'):
            name_parts = form_data.get('student_name').split()
            sem = form_data.get('semester')
            student_query = Student.query.filter(Student.semester == sem, Student.user_id == user_id_session)
            for part in name_parts:
                student_query = student_query.filter(Student.first_name.ilike(f'%{part}%') | Student.last_name.ilike(f'%{part}%'))
            student = student_query.first()
            if student:
                records = base_query.filter_by(student_id_ref=student.id).order_by(AttendanceRecord.date.desc()).all()
                report_title = f"Report for {student.first_name} {student.last_name} (Semester: {student.semester})"
            else: 
                return jsonify({'error': "Student not found with the provided name and semester under your account."}), 404
            
        elif form_data.get('report_date'):
            report_date = date.fromisoformat(form_data.get('report_date'))
            records = base_query.join(Student).filter(
                AttendanceRecord.date == report_date,
                Student.user_id == user_id_session
            ).order_by(Student.student_id).all()
            report_title = f"Report for {report_date.strftime('%B %d, %Y')}"
            
        elif form_data.get('semester_only'):
            sem = form_data.get('semester_only')
            records = base_query.join(Student).filter(
                Student.semester == sem,
                Student.user_id == user_id_session
            ).order_by(AttendanceRecord.date.desc(), Student.student_id).all()
            report_title = f"Full Report for Semester {sem}"

        else: return jsonify({'error': 'Invalid search query.'}), 400

        serialized_records = [{'date': r.date.isoformat(), 
                               'status': r.status, 
                               'student': {'student_id': r.student.student_id, 
                                           'first_name': r.student.first_name, 
                                           'last_name': r.student.last_name
                                           }} for r in records]
        return jsonify({'title': report_title, 'records': serialized_records})

    except Exception as e:
        app.logger.error(f"Error in generate_report: {e}", exc_info=True)
        return jsonify({'error': 'An unexpected server error occurred.'}), 500


# ----------------- FORGET PASSWORD ROUTE -------------------------- #

@app.route("/forget")
def forget():
    return render_template('forget.html')

@app.route('/send_otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'error': 'Email is required.'}), 400

    user = User.query.filter_by(email=email).first()
    if user:
        otp = str(random.randint(100000, 999999))
        session['otp_data'] = {
            'email': email,
            'otp': otp,
            'timestamp': time.time()
        }
        
        # --- SEND OTP VIA EMAIL ---
        try:
            msg_title = "Your OTP for Password Reset"
            sender = app.config['MAIL_DEFAULT_SENDER'] # Or a specific sender email
            msg = Message(msg_title, sender=sender, recipients=[email])
            msg.body = f"Your One-Time Password (OTP) for resetting your password is: {otp}\n" \
                       f"This OTP is valid for {OTP_EXPIRY_SECONDS // 60} minutes.\n" \
                       f"If you did not request this, please ignore this email."
            
            mail.send(msg)
            app.logger.info(f"OTP email sent to {email}. OTP (server log only): {otp}") # Log for your records
            # You can remove 'otp_dev_only' from the response now, or keep it for easier testing during dev
            return jsonify({'message': 'OTP has been sent to your email address.'}) 
        except Exception as e:
            app.logger.error(f"Failed to send OTP email to {email}: {e}")
            # Optionally, clear the session OTP data if email fails, or let user retry
            # session.pop('otp_data', None) 
            return jsonify({'error': 'Failed to send OTP email. Please try again later or contact support.'}), 500
        # --- END SEND OTP VIA EMAIL ---

    else:
        return jsonify({'error': 'Email not registered.'}), 404



@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp_entered = data.get('otp')

    if not email or not otp_entered:
        return jsonify({'error': 'Email and OTP are required.'}), 400

    otp_data = session.get('otp_data')

    if not otp_data:
        return jsonify({'error': 'OTP not generated or session expired. Please request a new OTP.'}), 400
    
    if otp_data.get('email') != email:
        # This case should ideally be prevented by frontend logic, but good to have a check
        return jsonify({'error': 'Email mismatch with OTP session. Please start over.'}), 400

    if (time.time() - otp_data.get('timestamp', 0)) > OTP_EXPIRY_SECONDS:
        session.pop('otp_data', None) # Clear expired OTP
        return jsonify({'error': 'OTP has expired. Please request a new one.'}), 400

    if otp_data.get('otp') == otp_entered:
        session['otp_verified_for_email'] = email # Mark as verified for this email
        # OTP data is kept in session until password reset or it expires
        return jsonify({'message': 'OTP verified successfully.'})
    else:
        return jsonify({'error': 'Invalid OTP.'}), 400

@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    new_password = data.get('new_password')

    if not email or not new_password:
        return jsonify({'error': 'Email and new password are required.'}), 400

    if session.get('otp_verified_for_email') != email:
        return jsonify({'error': 'OTP not verified or session mismatch. Please start over.'}), 403

    # Double check OTP data and expiry, in case of delay between verification and reset
    otp_data = session.get('otp_data')
    if not otp_data or otp_data.get('email') != email or \
       (time.time() - otp_data.get('timestamp', 0)) > OTP_EXPIRY_SECONDS:
        session.pop('otp_data', None)
        session.pop('otp_verified_for_email', None)
        return jsonify({'error': 'Session timed out or OTP data invalid. Please start the password reset process again.'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        session.pop('otp_data', None)
        session.pop('otp_verified_for_email', None)
        return jsonify({'error': 'User not found.'}), 404 # Should not happen if previous steps were correct

    if len(new_password) < 6: # Basic password policy, can be enhanced
        return jsonify({'error': 'Password must be at least 6 characters long.'}), 400

    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.password = hashed_password
    db.session.commit()

    # Clear OTP data from session after successful reset
    session.pop('otp_data', None)
    session.pop('otp_verified_for_email', None)

    # Flash message might not be seen due to JS redirect, but good for direct calls / fallback
    flash('Password has been reset successfully. Please log in.', 'success')
    return jsonify({'message': 'Password reset successfully. Redirecting to login...', 
                    'redirect_url': url_for('login')})






# --- APP STARTUP ---

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
#app.py
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from datetime import datetime, timedelta
import os
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('EMAIL_USER')

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

with app.app_context():
    try:
        mail.init_app(app)
        app.logger.info("Mail extension initialized successfully")
    except Exception as e:
        app.logger.error(f"Failed to initialize mail extension: {str(e)}")

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expiry = db.Column(db.DateTime)
    password_last_changed = db.Column(db.DateTime, default=datetime.utcnow)
    password_expiry_days = db.Column(db.Integer, default=90)  # 90 days default

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        self.password_last_changed = datetime.utcnow()
        db.session.commit()
        
    def is_password_expired(self):
        if not self.password_last_changed:
            return False
        expiry_date = self.password_last_changed + timedelta(days=self.password_expiry_days)
        return datetime.utcnow() > expiry_date

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_reset_token(self):
        # Generate a random token
        token = secrets.token_urlsafe(32)
        # Set token expiry to 1 hour from now
        self.reset_token = token
        self.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
        db.session.commit()
        return token

    @staticmethod
    def verify_reset_token(token):
        user = User.query.filter_by(reset_token=token).first()
        if user is None:
            return None
        if user.reset_token_expiry < datetime.utcnow():
            # Token has expired
            user.reset_token = None
            user.reset_token_expiry = None
            db.session.commit()
            return None
        return user

    def clear_reset_token(self):
        self.reset_token = None
        self.reset_token_expiry = None
        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('คำขอรีเซ็ตรหัสผ่าน',
                 recipients=[user.email])
    # Make sure to use reset_password_token as the endpoint name
    reset_url = url_for('reset_token', token=token, _external=True)
    msg.body = f'''สวัสดี {user.username},

เพื่อรีเซ็ตรหัสผ่านของคุณ กรุณาคลิกที่ลิงก์ด้านล่าง:

{reset_url}

ลิงก์นี้จะหมดอายุในอีก 1 ชั่วโมง

หากคุณไม่ได้ขอรีเซ็ตรหัสผ่าน กรุณาเพิกเฉยต่อข้อความนี้

ขอแสดงความนับถือ,
ทีมงานของเรา'''
    mail.send(msg)

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template('index.html')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = bool(request.form.get('remember_me'))

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if user.is_password_expired():
                flash('รหัสผ่านของคุณหมดอายุแล้ว กรุณาเปลี่ยนรหัสผ่านใหม่', 'warning')
                token = user.generate_reset_token()
                return redirect(url_for('reset_password', token=token))
            
            login_user(user, remember=remember)
            flash('เข้าสู่ระบบสำเร็จ!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        flash('ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง', 'error')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash('ชื่อผู้ใช้นี้ถูกใช้งานแล้ว', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('อีเมลนี้ถูกลงทะเบียนแล้ว', 'error')
            return redirect(url_for('register'))

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('ลงทะเบียนสำเร็จ! กรุณาเข้าสู่ระบบ', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            # Generate reset token
            token = user.generate_reset_token()
            
            # Create reset URL
            reset_url = url_for('reset_password', token=token, _external=True)
            
            # Send email
            try:
                msg = Message('Password Reset Request',
                            sender=app.config['MAIL_DEFAULT_SENDER'],
                            recipients=[user.email])
                msg.subject = "คำขอรีเซ็ตรหัสผ่าน"
                msg.body = f'''เรียน {user.username},

คุณได้ขอรีเซ็ตรหัสผ่านสำหรับบัญชีของคุณ คลิกลิงก์ด้านล่างเพื่อรีเซ็ตรหัสผ่าน:

{reset_url}

ลิงก์นี้จะหมดอายุในอีก 1 ชั่วโมง

หากคุณไม่ได้ขอรีเซ็ตรหัสผ่าน กรุณาเพิกเฉยต่อข้อความนี้

ขอแสดงความนับถือ,
ทีมงานของเรา'''
                
                mail.send(msg)
                flash('คำแนะนำในการรีเซ็ตรหัสผ่านได้ถูกส่งไปยังอีเมลของคุณแล้ว', 'success')
            except Exception as e:
                app.logger.error(f"Failed to send reset email: {str(e)}")
                flash('เกิดข้อผิดพลาดในการส่งอีเมล กรุณาลองใหม่อีกครั้ง', 'error')
        else:
            # Send generic message to prevent email enumeration
            flash('หากอีเมลนี้มีอยู่ในระบบ คุณจะได้รับอีเมลรีเซ็ตรหัสผ่านในไม่ช้า', 'info')

        return redirect(url_for('login'))

    return render_template('reset_request.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    user = User.verify_reset_token(token)
    if user is None:
        flash('ลิงก์รีเซ็ตรหัสผ่านไม่ถูกต้องหรือหมดอายุแล้ว', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Enhanced password validation
        if not password or len(password) < 12:
            flash('รหัสผ่านต้องมีความยาวอย่างน้อย 12 ตัวอักษร', 'error')
            return render_template('reset_token.html')

        if not any(c.isupper() for c in password):
            flash('รหัสผ่านต้องมีตัวพิมพ์ใหญ่อย่างน้อย 1 ตัว', 'error')
            return render_template('reset_token.html')

        if not any(c.islower() for c in password):
            flash('รหัสผ่านต้องมีตัวพิมพ์เล็กอย่างน้อย 1 ตัว', 'error')
            return render_template('reset_token.html')

        if not any(c.isdigit() for c in password):
            flash('รหัสผ่านต้องมีตัวเลขอย่างน้อย 1 ตัว', 'error')
            return render_template('reset_token.html')

        if not any(c in '!@#$%^&*(),.?":{}|<>' for c in password):
            flash('รหัสผ่านต้องมีอักขระพิเศษอย่างน้อย 1 ตัว', 'error')
            return render_template('reset_token.html')

        if password != confirm_password:
            flash('รหัสผ่านไม่ตรงกัน', 'error')
            return render_template('reset_token.html')

        user.set_password(password)
        user.clear_reset_token()
        flash('รหัสผ่านของคุณได้รับการเปลี่ยนแปลงแล้ว! กรุณาเข้าสู่ระบบ', 'success')
        return redirect(url_for('login'))

    return render_template('reset_token.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('ออกจากระบบสำเร็จ!', 'success')
    return redirect(url_for('login'))

# Initialize database
def init_db():
    with app.app_context():
        db.drop_all()
        db.create_all()

if __name__ == '__main__':
    init_db()  # Initialize database tables
    app.run(debug=True)
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'avatars')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'change-me-in-production-xyz123'),
    SQLALCHEMY_DATABASE_URI='sqlite:///visitors.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    MAX_CONTENT_LENGTH=4 * 1024 * 1024,  # 4 MB max upload
)

SMTP_HOST = os.environ.get('SMTP_HOST', '')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASS = os.environ.get('SMTP_PASS', '')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'warning'


# ── Models ──────────────────────────────────────────────────────────────────

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    office_number = db.Column(db.String(50), default='')
    phone = db.Column(db.String(30), default='')
    email = db.Column(db.String(120), default='')
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    avatar = db.Column(db.String(200), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    visits = db.relationship('Visit', backref='staff', lazy=True,
                             cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Visit(db.Model):
    __tablename__ = 'visits'
    id = db.Column(db.Integer, primary_key=True)
    visitor_name = db.Column(db.String(120), nullable=False)
    visitor_phone = db.Column(db.String(30), default='')
    purpose = db.Column(db.String(200), default='')
    staff_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    signed_in_at = db.Column(db.DateTime, default=datetime.utcnow)
    attended = db.Column(db.Boolean, default=False)
    attended_at = db.Column(db.DateTime)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ── Helpers ──────────────────────────────────────────────────────────────────

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def send_email(staff, visitor_name, visitor_phone, purpose):
    if not (SMTP_HOST and SMTP_USER and staff.email):
        return
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USER
        msg['To'] = staff.email
        msg['Subject'] = f'Visitor Alert: {visitor_name} has arrived'
        body = (
            f"Hello {staff.full_name},\n\n"
            f"A visitor has arrived to see you.\n\n"
            f"Name   : {visitor_name}\n"
            f"Phone  : {visitor_phone or 'N/A'}\n"
            f"Purpose: {purpose or 'N/A'}\n"
            f"Time   : {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
            f"Please attend to them at your earliest convenience."
        )
        msg.attach(MIMEText(body, 'plain'))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as srv:
            srv.starttls()
            srv.login(SMTP_USER, SMTP_PASS)
            srv.sendmail(SMTP_USER, staff.email, msg.as_string())
    except Exception:
        pass  # Don't fail sign-in if email fails


# ── Public Routes ─────────────────────────────────────────────────────────────

@app.route('/')
def index():
    staff_list = User.query.order_by(User.full_name).all()
    return render_template('visitor_signin.html', staff_list=staff_list)


@app.route('/signin', methods=['POST'])
def signin():
    name = request.form.get('visitor_name', '').strip()
    phone = request.form.get('visitor_phone', '').strip()
    purpose = request.form.get('purpose', '').strip()
    staff_id = request.form.get('staff_id', '').strip()

    if not name or not staff_id:
        flash('Please enter your name and select a staff member.', 'danger')
        return redirect(url_for('index'))

    staff = db.session.get(User, int(staff_id))
    if not staff:
        flash('Invalid staff selection.', 'danger')
        return redirect(url_for('index'))

    visit = Visit(visitor_name=name, visitor_phone=phone,
                  purpose=purpose, staff_id=staff.id)
    db.session.add(visit)
    db.session.commit()

    send_email(staff, name, phone, purpose)

    flash(f'Signed in successfully! {staff.full_name} has been notified. Please take a seat.', 'success')
    return redirect(url_for('index'))


# ── Auth Routes ───────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard' if current_user.is_admin else 'dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=True)
            next_page = request.args.get('next')
            return redirect(next_page or (url_for('admin_dashboard') if user.is_admin else url_for('dashboard')))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ── Staff Routes ──────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    visits = Visit.query.filter_by(staff_id=current_user.id)\
        .order_by(Visit.signed_in_at.desc()).all()
    pending = [v for v in visits if not v.attended]
    return render_template('staff_dashboard.html', visits=visits, pending_count=len(pending))


@app.route('/visit/<int:visit_id>/attend', methods=['POST'])
@login_required
def attend_visit(visit_id):
    visit = db.get_or_404(Visit, visit_id)
    if visit.staff_id != current_user.id and not current_user.is_admin:
        flash('Unauthorized.', 'danger')
        return redirect(url_for('dashboard'))
    visit.attended = True
    visit.attended_at = datetime.utcnow()
    db.session.commit()
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/api/new-visitors')
@login_required
def api_new_visitors():
    since_str = request.args.get('since', '')
    try:
        since = datetime.fromisoformat(since_str)
    except (TypeError, ValueError):
        since = datetime.utcnow()

    new_visits = Visit.query.filter(
        Visit.staff_id == current_user.id,
        Visit.signed_in_at > since,
        Visit.attended == False
    ).all()

    return jsonify([{
        'id': v.id,
        'visitor_name': v.visitor_name,
        'visitor_phone': v.visitor_phone,
        'purpose': v.purpose,
        'signed_in_at': v.signed_in_at.isoformat(),
    } for v in new_visits])


# ── Profile Routes (all logged-in staff) ─────────────────────────────────────

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.full_name = request.form.get('full_name', '').strip() or current_user.full_name
        current_user.phone = request.form.get('phone', '').strip()
        current_user.email = request.form.get('email', '').strip()
        current_user.office_number = request.form.get('office_number', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm = request.form.get('confirm_password', '').strip()
        if new_password:
            if new_password != confirm:
                flash('Passwords do not match.', 'danger')
                return redirect(url_for('profile'))
            if len(new_password) < 6:
                flash('Password must be at least 6 characters.', 'danger')
                return redirect(url_for('profile'))
            current_user.set_password(new_password)
        db.session.commit()
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html')


@app.route('/profile/avatar', methods=['POST'])
@login_required
def upload_avatar():
    file = request.files.get('avatar')
    if not file or file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(url_for('profile'))
    if not allowed_file(file.filename):
        flash('Allowed types: png, jpg, jpeg, gif, webp.', 'danger')
        return redirect(url_for('profile'))
    ext = file.filename.rsplit('.', 1)[1].lower()
    filename = f"user_{current_user.id}.{ext}"
    # Remove old avatar if different extension
    for old_ext in ALLOWED_EXTENSIONS:
        old_path = os.path.join(UPLOAD_FOLDER, f"user_{current_user.id}.{old_ext}")
        if os.path.exists(old_path) and old_ext != ext:
            os.remove(old_path)
    file.save(os.path.join(UPLOAD_FOLDER, filename))
    current_user.avatar = filename
    db.session.commit()
    flash('Profile picture updated.', 'success')
    return redirect(url_for('profile'))



# ── Admin Routes ──────────────────────────────────────────────────────────────

@app.route('/admin')
@admin_required
def admin_dashboard():
    today = datetime.utcnow().date()
    total_visits = Visit.query.count()
    today_visits = Visit.query.filter(
        db.func.date(Visit.signed_in_at) == today
    ).count()
    total_staff = User.query.count()
    pending_visits = Visit.query.filter_by(attended=False).count()
    recent_visits = Visit.query.order_by(Visit.signed_in_at.desc()).limit(10).all()
    return render_template('admin/dashboard.html',
        total_visits=total_visits, today_visits=today_visits,
        total_staff=total_staff, pending_visits=pending_visits,
        recent_visits=recent_visits)


@app.route('/admin/staff')
@admin_required
def admin_staff():
    staff = User.query.order_by(User.full_name).all()
    return render_template('admin/staff.html', staff=staff)


@app.route('/admin/staff/add', methods=['POST'])
@admin_required
def admin_add_staff():
    username = request.form.get('username', '').strip()
    full_name = request.form.get('full_name', '').strip()
    office = request.form.get('office_number', '').strip()
    phone = request.form.get('phone', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    is_admin = request.form.get('is_admin') == 'on'

    if not username or not full_name or not password:
        flash('Full name, username, and password are required.', 'danger')
        return redirect(url_for('admin_staff'))

    if User.query.filter_by(username=username).first():
        flash(f'Username "{username}" already exists.', 'danger')
        return redirect(url_for('admin_staff'))

    user = User(full_name=full_name, office_number=office, phone=phone,
                email=email, username=username, is_admin=is_admin)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    flash(f'Staff member "{full_name}" added successfully.', 'success')
    return redirect(url_for('admin_staff'))


@app.route('/admin/staff/edit/<int:user_id>', methods=['POST'])
@admin_required
def admin_edit_staff(user_id):
    user = db.get_or_404(User, user_id)
    user.full_name = request.form.get('full_name', user.full_name).strip()
    user.office_number = request.form.get('office_number', '').strip()
    user.phone = request.form.get('phone', '').strip()
    user.email = request.form.get('email', '').strip()
    user.is_admin = request.form.get('is_admin') == 'on'
    new_password = request.form.get('password', '').strip()
    if new_password:
        user.set_password(new_password)
    db.session.commit()
    flash(f'"{user.full_name}" updated successfully.', 'success')
    return redirect(url_for('admin_staff'))


@app.route('/admin/staff/delete/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_staff(user_id):
    user = db.get_or_404(User, user_id)
    if user.id == current_user.id:
        flash("You cannot delete your own account.", 'danger')
        return redirect(url_for('admin_staff'))
    name = user.full_name
    db.session.delete(user)
    db.session.commit()
    flash(f'"{name}" has been removed.', 'success')
    return redirect(url_for('admin_staff'))


@app.route('/admin/visitors')
@admin_required
def admin_visitors():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    query = Visit.query
    if search:
        query = query.filter(
            Visit.visitor_name.ilike(f'%{search}%') |
            Visit.visitor_phone.ilike(f'%{search}%') |
            Visit.purpose.ilike(f'%{search}%')
        )
    visits = query.order_by(Visit.signed_in_at.desc()).paginate(page=page, per_page=20, error_out=False)
    return render_template('admin/visitors.html', visits=visits, search=search)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Migrate: add avatar column if it doesn't exist yet
        from sqlalchemy import text
        with db.engine.connect() as conn:
            try:
                conn.execute(text("ALTER TABLE users ADD COLUMN avatar VARCHAR(200) DEFAULT ''"))
                conn.commit()
            except Exception:
                pass
        if not User.query.filter_by(is_admin=True).first():
            admin = User(full_name='Administrator', username='admin',
                         email='admin@example.com', is_admin=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print('[OK] Default admin created  ->  username: admin  |  password: admin123')
        print('[OK] Database ready')
    app.run(debug=True, port=5000)

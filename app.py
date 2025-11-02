from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

UPLOAD_FOLDER = 'uploads/'
ENCRYPTED_FOLDER = 'uploads/encrypted/'
DECRYPTED_FOLDER = 'uploads/decrypted/'
KEY_FOLDER = 'keys/'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)
os.makedirs(KEY_FOLDER, exist_ok=True)

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Try again.', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user_folder = os.path.join(UPLOAD_FOLDER, f"user_{current_user.id}")
    encrypted_folder = os.path.join(user_folder, "encrypted")
    decrypted_folder = os.path.join(user_folder, "decrypted")

    # Ensure the folders exist
    os.makedirs(encrypted_folder, exist_ok=True)
    os.makedirs(decrypted_folder, exist_ok=True)

    encrypted_files = os.listdir(encrypted_folder) if os.path.exists(encrypted_folder) else []
    decrypted_files = os.listdir(decrypted_folder) if os.path.exists(decrypted_folder) else []

    return render_template(
        'dashboard.html',
        username=current_user.username,
        encrypted_files=encrypted_files,
        decrypted_files=decrypted_files,
        encrypted_folder="encrypted",
        decrypted_folder="decrypted"
    )

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('dashboard'))

    user_folder = os.path.join(UPLOAD_FOLDER, f"user_{current_user.id}", "encrypted")
    os.makedirs(user_folder, exist_ok=True)  # Create user-specific folder if it doesn't exist

    file_path = os.path.join(user_folder, file.filename + '.enc')
    encrypt_file(file, file_path)
    
    flash('File encrypted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/decrypt', methods=['POST'])
@login_required
def decrypt_uploaded_file():
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('dashboard'))

    user_folder = os.path.join(UPLOAD_FOLDER, f"user_{current_user.id}")
    encrypted_path = os.path.join(user_folder, "encrypted", file.filename)
    decrypted_path = os.path.join(user_folder, "decrypted", file.filename.replace('.enc', ''))

    if not os.path.exists(encrypted_path):
        flash('File not found!', 'danger')
        return redirect(url_for('dashboard'))

    decrypt_file(encrypted_path, decrypted_path)
    flash('File decrypted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/download/<folder>/<filename>')
@login_required
def download_file(folder, filename):
    if folder not in ["encrypted", "decrypted"]:
        flash("Invalid download request!", "danger")
        return redirect(url_for("dashboard"))

    user_folder = os.path.join(UPLOAD_FOLDER, f"user_{current_user.id}", folder)
    file_path = os.path.join(user_folder, filename)

    if not os.path.exists(file_path):
        flash("Unauthorized access or file not found!", "danger")
        return redirect(url_for("dashboard"))

    return send_from_directory(user_folder, filename, as_attachment=True)

# Encryption Logic
def generate_key():
    key = Fernet.generate_key()
    with open(os.path.join(KEY_FOLDER, 'secret.key'), 'wb') as key_file:
        key_file.write(key)
    return key

def load_key():
    return open(os.path.join(KEY_FOLDER, 'secret.key'), 'rb').read()

def encrypt_file(file, file_path):
    key = load_key()
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(file.read())
    with open(file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)

def decrypt_file(file_path, output_path):
    key = load_key()
    cipher = Fernet(key)
    with open(file_path, 'rb') as encrypted_file:
        decrypted_data = cipher.decrypt(encrypted_file.read())
    with open(output_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not os.path.exists(os.path.join(KEY_FOLDER, 'secret.key')):
            generate_key()
    app.run(debug=True)
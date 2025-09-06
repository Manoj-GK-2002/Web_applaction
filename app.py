# app.py
# Main application file for the Flask user authentication system.

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from passlib.hash import sha256_crypt
from functools import wraps
import yaml

app = Flask(__name__)

# --- DATABASE CONFIGURATION ---
# Load database configuration from a YAML file for security.
# Make sure you have a 'db.yaml' file in the same directory.
db_config = yaml.safe_load(open('db.yaml'))
app.config['MYSQL_HOST'] = db_config['mysql_host']
app.config['MYSQL_USER'] = db_config['mysql_user']
app.config['MYSQL_PASSWORD'] = db_config['mysql_password']
app.config['MYSQL_DB'] = db_config['mysql_db']
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'  # Returns results as dictionaries

# --- SECRET KEY CONFIGURATION ---
# A secret key is required for session management.
# Keep this key secret in a real application.
app.config['SECRET_KEY'] = 'your_super_secret_key_12345'

# Initialize MySQL
mysql = MySQL(app)


# --- DECORATORS ---
# Decorator to check if a user is logged in.
# This prevents unauthorized access to certain routes.
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login first.', 'danger')
            return redirect(url_for('login'))

    return wrap


# --- ROUTES ---

# Home Page / Dashboard
@app.route('/')
@is_logged_in
def home():
    """
    Displays the home page, accessible only to logged-in users.
    """
    return render_template('home.html', username=session['username'])


# User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handles user registration.
    GET: Displays the registration form.
    POST: Processes the form data, validates it, and creates a new user.
    """
    if request.method == 'POST':
        # Get form fields
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Basic validation
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return render_template('register.html')

        # Create a database cursor
        cur = mysql.connection.cursor()

        # Check if username already exists
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            flash('Username is already taken.', 'danger')
            cur.close()
            return render_template('register.html')
        else:
            # Hash the password before storing
            hashed_password = sha256_crypt.encrypt(str(password))

            # Insert new user into the database
            cur.execute("INSERT INTO users(username, password) VALUES(%s, %s)", (username, hashed_password))

            # Commit to DB
            mysql.connection.commit()

            # Close connection
            cur.close()

            flash('You are now registered and can log in!', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')


# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user login.
    GET: Displays the login form.
    POST: Authenticates the user and creates a session.
    """
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            stored_password_hash = data['password']
            cur.close()

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, stored_password_hash):
                # Passwords match, create session
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in.', 'success')
                return redirect(url_for('home'))
            else:
                # Passwords do not match
                flash('Invalid login credentials.', 'danger')
                return render_template('login.html')
        else:
            # Username not found
            cur.close()
            flash('Username not found.', 'danger')
            return render_template('login.html')

    return render_template('login.html')


# User Logout
@app.route('/logout')
@is_logged_in
def logout():
    """
    Logs the user out by clearing the session.
    """
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


# --- MAIN EXECUTION ---
if __name__ == '__main__':
    # Make sure to set debug=False in a production environment
    app.run(debug=True)

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import smtplib
from email.mime.text import MIMEText
from itsdangerous import URLSafeTimedSerializer
import pymysql
import requests
import os
from dotenv import load_dotenv


load_dotenv()


# Configuration
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY')

# SMTP2GO Email Server
SMTP_SERVER = 'mail.smtp2go.com'
SMTP_PORT = 587
EMAIL_ADDRESS = os.environ.get("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")




bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

serializer = URLSafeTimedSerializer(app.secret_key)

# Google API
GOOGLE_FACTCHECK_API_KEY = os.environ.get("GOOGLE_FACTCHECK_API_KEY")

# ---------------------
# Database Connection
# ---------------------
print("Connecting with:", {
    "host": os.environ.get("DB_HOST"),
    "port": os.environ.get("DB_PORT"),
    "user": os.environ.get("DB_USER"),
    "password": os.environ.get("DB_PASSWORD"),
    "database": os.environ.get("DB_NAME"),
})

def get_db_connection():
    return pymysql.connect(
        host=os.environ.get("DB_HOST"),
        port=int(os.environ.get("DB_PORT")),
        user=os.environ.get("DB_USER"),
        password=os.environ.get("DB_PASSWORD"),
        database=os.environ.get("DB_NAME"),
        cursorclass=pymysql.cursors.DictCursor,
        ssl={"ssl": {}}
    )
    



# ---------------------
# User Model
# ---------------------
class User(UserMixin):
    def __init__(self, id, email, password, confirmed=False):
        self.id = id
        self.email = email
        self.password = password
        self.confirmed = confirmed

    def get_id(self):
        return str(self.id)

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def set_password(self, new_password):
        hashed_pw = bcrypt.generate_password_hash(new_password).decode('utf-8')
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("UPDATE accounts SET password = %s WHERE id = %s", (hashed_pw, self.id))
            conn.commit()
        conn.close()

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM accounts WHERE id = %s", (user_id,))
        user = cursor.fetchone()
    conn.close()
    if user:
        return User(user['id'], user['email'], user['password'], user['confirmed'])
    return None

# ---------------------
# Email Sending
# ---------------------
def send_confirmation_email(email):
    token = serializer.dumps(email, salt='email-confirmation')
    confirm_url = url_for('confirm_email', token=token, _external=True)

    subject = "Please Confirm Your Email"
    body = f" Hello [User], Thank you for signing up at our Fake News Website! We're excited to have you on board. To complete your registration, please confirm your email address by clicking the button below !\n\n🔵 Confirm your email:\n{confirm_url} \n\n If you did not create an account with us, you can safely ignore this email. \n\n Need help? Feel free to reply to this email — our team is here for you!"

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = email

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, [email], msg.as_string())
        server.quit()
        print(f"Confirmation email sent to {email}")
    except Exception as e:
        print(f"Error sending confirmation email: {e}")

def generate_token(email, salt):
    return serializer.dumps(email, salt=salt)

def confirm_token(token, salt='email-confirmation'):
    try:
        email = serializer.loads(token, salt=salt)
        return email
    except Exception:
        return False

# ---------------------
# Fact Checking API
# ---------------------
def fact_check_with_google(claim):
    url = f"https://factchecktools.googleapis.com/v1alpha1/claims:search?query={claim}&key={GOOGLE_FACTCHECK_API_KEY}"
    try:
        response = requests.get(url)
        data = response.json()
        if "claims" in data and data["claims"]:
            claim_data = data["claims"][0]
            rating = claim_data["claimReview"][0].get("textualRating", "Unrated")
            source_url = claim_data["claimReview"][0].get("url", "#")
            source = claim_data["claimReview"][0].get("publisher", {}).get("name", "Unknown")

            # --- Here is the key change ---
            result_html = f"""
                ✅ Verified by <strong>{source}</strong> — <em>{rating}</em><br>
                <a href="{source_url}" target="_blank" style="color: #4a90e2; font-weight: bold;">🔗 View Source</a>
            """
            return result_html
        else:
            return "❌ Could not verify this claim."
    except Exception as e:
        return f"Error: {str(e)}"


# ---------------------
# Routes
# ---------------------
@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    news = ""
    
    if request.method == "POST":
        news = request.form.get("news", "").strip()
        if news:
            result = fact_check_with_google(news)

            # Save to database if user is logged in
            if current_user.is_authenticated:
                conn = get_db_connection()
                try:
                    with conn.cursor() as cursor:
                        cursor.execute("""
                            INSERT INTO news_checks (user_id, email, news_text, result)
                            VALUES (%s, %s, %s, %s)
                        """, (current_user.id, current_user.email, news, result))
                        conn.commit()
                except Exception as e:
                    print(f"Error saving to history: {e}")
                finally:
                    conn.close()

    return render_template("index.html", result=result, news=news)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not email or not password:
            flash("Email and password are required.", "danger")
            return redirect(url_for('register'))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('register'))

        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM accounts WHERE email = %s", (email,))
            if cursor.fetchone():
                flash("Email already registered.", "danger")
                return redirect(url_for('login'))

            hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
            cursor.execute(
                "INSERT INTO accounts (email, password, confirmed) VALUES (%s, %s, %s)",
                (email, hashed_pw, False)
            )
            conn.commit()
        conn.close()

        send_confirmation_email(email)
        flash("Registered successfully! Please check your email to confirm.", "success")
        return redirect(url_for('login'))

    return render_template("register.html")

@app.route("/confirm/<token>")
def confirm_email(token):
    email = confirm_token(token)

    if not email:
        flash("Invalid confirmation link.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT confirmed FROM accounts WHERE email = %s", (email,))
            user = cursor.fetchone()

            if user and user['confirmed']:
                flash("Account already confirmed. Please login.", "info")
            else:
                cursor.execute("UPDATE accounts SET confirmed = 1 WHERE email = %s", (email,))
                conn.commit()
                flash("Your email has been confirmed!", "success")
    except Exception as e:
        print(f"Error confirming email: {e}")
        flash("An error occurred during confirmation.", "danger")
    finally:
        conn.close()

    return redirect(url_for('login'))

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM accounts WHERE email = %s", (email,))
            user = cursor.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user['password'], password):
            if not user['confirmed']:
                flash("Please confirm your email first.", "warning")
                return redirect(url_for('login'))
            login_user(User(user['id'], user['email'], user['password'], user['confirmed']))
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials.", "danger")
    return render_template("login.html")

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    result = None
    conn = get_db_connection()
    if request.method == "POST":
        news = request.form.get("news", "").strip()
        if news:
            result = fact_check_with_google(news)
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO news_checks (user_id, email, news_text, result) VALUES (%s, %s, %s, %s)",
                    (current_user.id, current_user.email, news, result)
                )
                conn.commit()

    with conn.cursor() as cursor:
        cursor.execute(
            "SELECT id, news_text, result, timestamp FROM news_checks WHERE user_id = %s ORDER BY timestamp DESC",
            (current_user.id,)
        )
        history = cursor.fetchall()
    conn.close()
    return render_template("dashboard.html", result=result, history=history)

@app.route("/delete_news_check/<int:news_id>", methods=["POST"])
@login_required
def delete_news_check(news_id):
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("DELETE FROM news_checks WHERE id = %s AND user_id = %s", (news_id, current_user.id))
        conn.commit()
    conn.close()
    flash("Entry deleted successfully.", "success")
    return redirect(url_for('dashboard'))

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current = request.form['current_password']
        new = request.form['new_password']
        confirm = request.form['confirm_password']

        if not current_user.check_password(current):
            flash("Current password is incorrect.", "danger")
        elif new != confirm:
            flash("New passwords do not match.", "danger")
        elif len(new) < 6:
            flash("Password must be at least 6 characters long.", "danger")
        else:
            current_user.set_password(new)
            flash("Password updated successfully!", "success")
            return redirect(url_for('dashboard'))

    return render_template("change-password.html")

@app.route("/how-it-works")
def how_it_works():
    return render_template("how-it-works.html")

@app.route("/privacy-policy")
def privacy_policy():
    return render_template("privacy-policy.html")

@app.route("/terms-and-conditions")
def terms_and_conditions():
    return render_template("terms-and-conditions.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

# ---------------------
# Run Server
# ---------------------
if __name__ == "__main__":
    app.run(debug=True)

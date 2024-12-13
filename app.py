from quart import Quart, request, jsonify
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.hash import bcrypt
from datetime import datetime, timedelta
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Quart(__name__)

# MongoDB Configuration
MONGO_URI = "mongodb://localhost:27017"
client = AsyncIOMotorClient(MONGO_URI)
db = client.groupify_assist
users_collection = db.users
email_verification_collection = db.email_verifications

# Utility function to hash passwords
def hash_password(password):
    return bcrypt.hash(password)

# Utility function to send email
def send_email(to_email, subject, body):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = "your_email@gmail.com"
    sender_password = "your_app_password"

    # Create a multi-part message
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = subject

    # Add text and HTML parts
    msg.attach(MIMEText(body, 'plain'))  # Plain text
    msg.attach(MIMEText(f"<html><body><p>{body}</p></body></html>", 'html'))  # HTML

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, msg.as_string())
            print("Email sent successfully.")
    except Exception as e:
        print(f"Failed to send email: {e}")

@app.route('/register', methods=['POST'])
async def register():
    data = await request.json
    email = data.get('email')
    password = data.get('password')
    country = data.get('country')

    # Validate required fields
    if not email or not password or not country:
        return jsonify({"error": "Email, password, and country are required."}), 400

    # Check if user already exists
    existing_user = await users_collection.find_one({"email": email})
    if existing_user:
        return jsonify({"error": "Email is already registered."}), 409

    # Create new user
    new_user = {
        "email": email,
        "password_hash": hash_password(password),
        "country": country,
        "is_confirmed": False,
        "created_at": datetime.utcnow()
    }
    result = await users_collection.insert_one(new_user)

    # Generate and store email verification code
    verification_code = secrets.token_hex(16)
    verification_entry = {
        "user_id": result.inserted_id,
        "code": verification_code,
        "expires_at": datetime.utcnow() + timedelta(hours=1)
    }
    await email_verification_collection.insert_one(verification_entry)

    # Send verification email
    email_body = f"Please verify your email by using the following code: {verification_code}"
    send_email(email, "Email Verification", email_body)

    return jsonify({"message": "User registered successfully. Please verify your email.", "user_id": str(result.inserted_id)}), 201

@app.route('/confirm-email', methods=['POST'])
async def confirm_email():
    data = await request.json
    email = data.get('email')
    code = data.get('code')

    # Validate required fields
    if not email or not code:
        return jsonify({"error": "Email and code are required."}), 400

    # Find user
    user = await users_collection.find_one({"email": email})
    if not user:
        return jsonify({"error": "User not found."}), 404

    # Find and validate verification code
    verification_entry = await email_verification_collection.find_one({"user_id": user['_id'], "code": code})
    if not verification_entry:
        return jsonify({"error": "Invalid or expired verification code."}), 400

    if verification_entry['expires_at'] < datetime.utcnow():
        return jsonify({"error": "Verification code has expired."}), 400

    # Confirm user's email
    await users_collection.update_one({"_id": user['_id']}, {"$set": {"is_confirmed": True}})
    await email_verification_collection.delete_one({"_id": verification_entry['_id']})

    return jsonify({"message": "Email confirmed successfully."}), 200

@app.route('/login', methods=['POST'])
async def login():
    data = await request.json
    email = data.get('email')
    password = data.get('password')

    # Validate required fields
    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400

    # Find user by email
    user = await users_collection.find_one({"email": email})
    if not user or not bcrypt.verify(password, user['password_hash']):
        return jsonify({"error": "Invalid email or password."}), 401

    if not user['is_confirmed']:
        return jsonify({"error": "Email not confirmed."}), 403

    return jsonify({"message": "Login successful.", "user_id": str(user['_id'])}), 200

if __name__ == '__main__':
    app.run(debug=True)

from quart import Quart, request, jsonify
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.hash import bcrypt
from datetime import datetime

app = Quart(__name__)

# MongoDB Configuration
MONGO_URI = "mongodb://localhost:27017"
client = AsyncIOMotorClient(MONGO_URI)
db = client.groupify_assist
users_collection = db.users

# Utility function to hash passwords
def hash_password(password):
    return bcrypt.hash(password)

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

    return jsonify({"message": "User registered successfully.", "user_id": str(result.inserted_id)}), 201

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

    return jsonify({"message": "Login successful.", "user_id": str(user['_id'])}), 200

if __name__ == '__main__':
    app.run(debug=True)

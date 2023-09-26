from flask import Flask, request, jsonify
import jwt
import json
from cryptography.fernet import Fernet

app = Flask(__name__)

# Replace 'your_secret_key' with your actual secret key for JWT and Fernet encryption.
JWT_SECRET_KEY = 'your_secret_key'
FERNET_KEY = Fernet.generate_key()

# Health check endpoint
@app.route('/', methods=['GET'])
def health_check():
    return 'Healthy'

# Authentication endpoint
@app.route('/auth', methods=['POST'])
def authenticate():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # You can implement your own authentication logic here
    # For simplicity, let's assume email and password are valid
    # Generate a JWT token
    payload = {'email': email}
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')

    return jsonify({'token': token})

# Contents endpoint
@app.route('/contents', methods=['GET'])
def get_contents():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({'message': 'Missing JWT token'}), 401

    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
        email = payload.get('email')
        
        # You can add your own logic to fetch and decrypt content here
        # For simplicity, let's assume some example content
        fernet = Fernet(FERNET_KEY)
        encrypted_content = fernet.encrypt(b'Some secret content for ' + email.encode())
        
        return jsonify({'content': encrypted_content.decode()})
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.DecodeError:
        return jsonify({'message': 'Invalid token'}), 401

if __name__ == '__main__':
    app.run(debug=True)

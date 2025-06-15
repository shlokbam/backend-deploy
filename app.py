from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import os
import google.generativeai as genai
from datetime import datetime, timedelta
from firebase_admin import credentials, initialize_app, firestore, auth
import firebase_admin
import json
import re
import jwt
from functools import wraps
import requests

# Load environment variables
load_dotenv()

# Debug: Print all environment variables
print("\nEnvironment Variables:")
print("FIREBASE_PROJECT_ID:", os.getenv('FIREBASE_PROJECT_ID'))
print("FIREBASE_PRIVATE_KEY_ID:", os.getenv('FIREBASE_PRIVATE_KEY_ID'))
print("FIREBASE_PRIVATE_KEY:", "Present" if os.getenv('FIREBASE_PRIVATE_KEY') else "Missing")
print("FIREBASE_CLIENT_EMAIL:", os.getenv('FIREBASE_CLIENT_EMAIL'))
print("FIREBASE_CLIENT_ID:", os.getenv('FIREBASE_CLIENT_ID'))
print("FIREBASE_CLIENT_CERT_URL:", os.getenv('FIREBASE_CLIENT_CERT_URL'))
print("GEMINI_API_KEY:", "Present" if os.getenv('GEMINI_API_KEY') else "Missing")
print("\n")

app = Flask(__name__)
# Configure CORS for Edge extension
CORS(app, resources={
    r"/api/*": {
        "origins": [
            "chrome-extension://*",  # Chrome extensions
            "edge-extension://*",    # Edge extensions
            "moz-extension://*"      # Firefox extensions
        ],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

# JWT Configuration
JWT_SECRET = os.getenv('JWT_SECRET', 'your-secret-key')  # Change this in production
JWT_ALGORITHM = 'HS256'

# Initialize Gemini
gemini_api_key = os.getenv('GEMINI_API_KEY')
if not gemini_api_key:
    print("Warning: GEMINI_API_KEY is not set")
else:
    genai.configure(api_key=gemini_api_key)
    model = genai.GenerativeModel('gemini-1.5-pro-002')
    print("Gemini API key initialized")

# Initialize Firebase Admin SDK
try:
    print("Loading Firebase credentials...")
    
    # Get the private key and handle it safely
    private_key = os.getenv('FIREBASE_PRIVATE_KEY')
    if not private_key:
        raise ValueError("FIREBASE_PRIVATE_KEY is not set in environment variables")
    
    cred = credentials.Certificate({
        "type": "service_account",
        "project_id": os.getenv('FIREBASE_PROJECT_ID'),
        "private_key_id": os.getenv('FIREBASE_PRIVATE_KEY_ID'),
        "private_key": private_key.replace('\\n', '\n'),
        "client_email": os.getenv('FIREBASE_CLIENT_EMAIL'),
        "client_id": os.getenv('FIREBASE_CLIENT_ID'),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": os.getenv('FIREBASE_CLIENT_CERT_URL')
    })
    
    print("Initializing Firebase Admin SDK...")
    firebase_admin.initialize_app(cred)
    db = firestore.client()
    print("Firebase Admin SDK initialized successfully!")

except Exception as e:
    print(f"Error initializing Firebase: {str(e)}")
    raise e

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            print(f"\nValidating token...")
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            print(f"Token decoded successfully. User ID: {data['uid']}")
            
            user_ref = db.collection('users').document(data['uid'])
            current_user = user_ref.get()
            
            if not current_user.exists:
                print(f"User document not found for ID: {data['uid']}")
                # Create the user document if it doesn't exist
                try:
                    print(f"Creating user document for ID: {data['uid']}")
                    user_ref.set({
                        'email': data['email'],
                        'created_at': datetime.now(),
                        'knowledge_base': []
                    })
                    current_user = user_ref.get()
                    print("User document created successfully")
                except Exception as e:
                    print(f"Error creating user document: {str(e)}")
                    return jsonify({'message': 'Error creating user document'}), 500
            
            return f(current_user, *args, **kwargs)
        except Exception as e:
            print(f"Token validation error: {str(e)}")
            return jsonify({'message': 'Token is invalid'}), 401
    
    return decorated

# Authentication endpoints
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        try:
            # Create user in Firebase Auth
            user = auth.create_user(
                email=email,
                password=password
            )
            
            # Create user document in Firestore
            user_data = {
                'email': email,
                'created_at': datetime.now(),
                'knowledge_base': []
            }
            db.collection('users').document(user.uid).set(user_data)
            
            # Generate JWT token
            token = jwt.encode({
                'uid': user.uid,
                'email': email,
                'exp': datetime.utcnow() + timedelta(days=1)
            }, JWT_SECRET, algorithm=JWT_ALGORITHM)
            
            return jsonify({
                'token': token,
                'user': {
                    'uid': user.uid,
                    'email': email
                }
            }), 201
            
        except auth.EmailAlreadyExistsError:
            return jsonify({'error': 'Email already exists'}), 400
        except Exception as e:
            return jsonify({'error': str(e)}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        print(f"\nLogin attempt for email: {email}")
        
        if not email or not password:
            print("Error: Email or password missing")
            return jsonify({'error': 'Email and password are required'}), 400
        
        try:
            # Get user by email
            print("Attempting to get user from Firebase...")
            user = auth.get_user_by_email(email)
            print(f"User found in Firebase: {user.uid}")
            
            # Sign in with email and password to verify credentials
            sign_in_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={os.getenv('FIREBASE_API_KEY')}"
            sign_in_data = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }
            
            response = requests.post(sign_in_url, json=sign_in_data)
            if not response.ok:
                print(f"Firebase sign in failed: {response.text}")
                return jsonify({'error': 'Invalid credentials'}), 401
            
            # Generate JWT token
            token = jwt.encode({
                'uid': user.uid,
                'email': email,
                'exp': datetime.utcnow() + timedelta(days=1)
            }, JWT_SECRET, algorithm=JWT_ALGORITHM)
            
            print("JWT token generated successfully")
            
            return jsonify({
                'token': token,
                'user': {
                    'uid': user.uid,
                    'email': email
                }
            })
            
        except auth.UserNotFoundError:
            print("Error: User not found in Firebase")
            return jsonify({'error': 'User not found'}), 401
        except Exception as e:
            print(f"Firebase error: {str(e)}")
            return jsonify({'error': 'Authentication failed'}), 401
        
    except Exception as e:
        print(f"General error: {str(e)}")
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/validate-token', methods=['GET'])
@token_required
def validate_token(current_user):
    return jsonify({
        'user': {
            'uid': current_user.id,
            'email': current_user.get('email')
        }
    })

# Q&A Management endpoints
@app.route('/api/qa', methods=['GET'])
@token_required
def get_qa_items(current_user):
    try:
        qa_ref = db.collection('users').document(current_user.id).collection('knowledge_base')
        qa_docs = qa_ref.get()
        
        qa_items = []
        for doc in qa_docs:
            qa_data = doc.to_dict()
            qa_items.append({
                'id': doc.id,
                'question': qa_data.get('question', ''),
                'answer': qa_data.get('answer', '')
            })
        
        return jsonify(qa_items)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/qa', methods=['POST'])
@token_required
def add_qa_item(current_user):
    try:
        data = request.get_json()
        question = data.get('question')
        answer = data.get('answer')
        
        if not question or not answer:
            return jsonify({'error': 'Question and answer are required'}), 400
        
        qa_ref = db.collection('users').document(current_user.id).collection('knowledge_base')
        qa_doc = qa_ref.add({
            'question': question,
            'answer': answer,
            'created_at': datetime.now()
        })
        
        return jsonify({
            'id': qa_doc[1].id,
            'question': question,
            'answer': answer
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/qa/<qa_id>', methods=['PUT'])
@token_required
def update_qa_item(current_user, qa_id):
    try:
        data = request.get_json()
        question = data.get('question')
        answer = data.get('answer')
        
        if not question or not answer:
            return jsonify({'error': 'Question and answer are required'}), 400
        
        qa_ref = db.collection('users').document(current_user.id).collection('knowledge_base').document(qa_id)
        qa_ref.update({
                            'question': question,
            'answer': answer,
            'updated_at': datetime.now()
        })
        
        return jsonify({
            'id': qa_id,
                        'question': question,
            'answer': answer
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/qa/<qa_id>', methods=['DELETE'])
@token_required
def delete_qa_item(current_user, qa_id):
    try:
        qa_ref = db.collection('users').document(current_user.id).collection('knowledge_base').document(qa_id)
        qa_ref.delete()
        return jsonify({'message': 'Q&A item deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Profile Management endpoints
@app.route('/api/change-password', methods=['POST'])
@token_required
def change_password(current_user):
    try:
        data = request.get_json()
        new_password = data.get('password')
        
        if not new_password:
            return jsonify({'error': 'New password is required'}), 400
        
        print(f"Updating password for user: {current_user.id}")
        
        # Update password in Firebase Auth
        auth.update_user(
            current_user.id,
            password=new_password
        )
        
        # Verify the password was updated by attempting to sign in
        sign_in_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={os.getenv('FIREBASE_API_KEY')}"
        sign_in_data = {
            "email": current_user.get('email'),
            "password": new_password,
            "returnSecureToken": True
        }
        
        response = requests.post(sign_in_url, json=sign_in_data)
        if not response.ok:
            print(f"Password verification failed: {response.text}")
            return jsonify({'error': 'Failed to verify password update'}), 500
        
        print("Password updated and verified successfully")
        return jsonify({'message': 'Password updated successfully'})
        
    except Exception as e:
        print(f"Error updating password: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Form Processing endpoint
@app.route('/api/process-form', methods=['POST'])
@token_required
def process_form(current_user):
    try:
        data = request.get_json()
        questions = data.get('questions', [])
        
        # Get user's knowledge base
        kb_ref = db.collection('users').document(current_user.id).collection('knowledge_base')
        
        # Get all Q&A items
        qa_items = kb_ref.stream()
        qa_list = [{'id': qa.id, **qa.to_dict()} for qa in qa_items]
        
        print(f"\nProcessing form with {len(questions)} questions")
        print(f"Found {len(qa_list)} Q&A items in knowledge base")
        
        answers = []
        for question in questions:
            # Normalize the question
            normalized_question = question['question'].lower().strip()
            print(f"\nProcessing question: {normalized_question}")
            
            # Find matching Q&A item using word-based matching
            matching_qa = None
            best_match_score = 0
            
            for qa in qa_list:
                qa_question = qa['question'].lower().strip()
                print(f"Comparing with Q&A: {qa_question}")
                
                # Split questions into words
                form_words = set(normalized_question.split())
                qa_words = set(qa_question.split())
                
                # Calculate word overlap
                common_words = form_words.intersection(qa_words)
                match_score = len(common_words) / max(len(form_words), len(qa_words))
                
                print(f"Match score: {match_score:.2f} (common words: {common_words})")
                
                # Update best match if this score is higher
                if match_score > best_match_score:
                    best_match_score = match_score
                    matching_qa = qa
            
            # Use a threshold to determine if the match is good enough
            if matching_qa and best_match_score >= 0.3:  # 30% word overlap threshold
                answers.append({
                    'question': question['question'],
                    'answer': matching_qa['answer'],
                    'matched_question': matching_qa['question'],
                    'match_score': best_match_score
                })
                print(f"Found match (score: {best_match_score:.2f}): {matching_qa['question']}")
                print(f"Added answer: {matching_qa['answer']}")
            else:
                print(f"No good match found for: {normalized_question}")
        
        print(f"\nReturning {len(answers)} answers")
        return jsonify(answers)
    except Exception as e:
        print(f"Error processing form: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True) 
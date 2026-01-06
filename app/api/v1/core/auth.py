from flask import request, jsonify, current_app, g
from app.api.v1 import api_v1_bp
from app.models.user import User
from app.extensions.db import db
from functools import wraps
import jwt
import datetime
import uuid

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'success': False, 'error': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(uuid.UUID(data['user_id']))
            if not current_user:
                raise Exception("User not found")
            
            # Set global user for this request
            g.current_user = current_user
            
        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'error': 'Token has expired'}), 401
        except Exception as e:
            return jsonify({'success': False, 'error': 'Token is invalid'}), 401
            
        return f(*args, **kwargs)
    
    return decorated

@api_v1_bp.route('/auth/login', methods=['POST'])
def api_login():
    """
    Login endpoint to get JWT token
    """
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'success': False, 'error': 'Username and password required'}), 400
    
    user = User.query.filter_by(username=data['username']).first()
    
    if not user or not user.check_password(data['password']):
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
        
    # Generate Token
    # Generate Token
    token = user.encode_auth_token(current_app.config['SECRET_KEY'])
    # Handle if token generation failed (returned Exception)
    if isinstance(token, Exception):
        return jsonify({'success': False, 'error': str(token)}), 500
        
    # Since jwt 2.0+ encode returns string, earlier versions bytes.
    # In PyJWT > 2, it is string. In < 2, bytes.
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    
    return jsonify({
        'success': True,
        'token': token,
        'user': {
            'id': str(user.id),
            'username': user.username,
            'email': user.email,
            'full_name': user.full_name
        }
    })

@api_v1_bp.route('/auth/me', methods=['GET'])
@token_required
def api_me():
    """
    Get current user info
    """
    user = g.current_user
    return jsonify({
        'success': True,
        'data': {
            'id': str(user.id),
            'username': user.username,
            'email': user.email,
            'full_name': user.full_name,
            'position': user.position
        }
    })

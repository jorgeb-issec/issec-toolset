from flask import Blueprint, render_template, g, request, jsonify
from flask_login import login_required
from app.decorators import company_required, product_required
from app.models.equipo import Equipo

log_bp = Blueprint('log_analytics', __name__, url_prefix='/logs')

@log_bp.route('/')
@login_required
@company_required
@product_required('log_analyzer')
def index():
    """Main Log Analyzer Dashboard"""
    from flask import current_app
    from flask_login import current_user
    
    # Get devices for filter
    devices = g.tenant_session.query(Equipo).all()
    
    # Generate API Token for frontend JS
    token = current_user.encode_auth_token(current_app.config['SECRET_KEY'])
    if isinstance(token, bytes):
        token = token.decode('utf-8')
        
    return render_template('logs/index.html', devices=devices, api_token=token)

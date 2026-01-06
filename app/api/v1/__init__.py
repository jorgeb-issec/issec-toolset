"""
API v1 Blueprint
All REST API endpoints are registered here with prefix /api/v1
"""
from flask import Blueprint

api_v1_bp = Blueprint('api_v1', __name__, url_prefix='/api/v1')

# Import and register endpoint modules
from app.api.v1.core import devices
from app.api.v1.policy_explorer import policies, reports
from app.api.v1.log_analyzer import logs


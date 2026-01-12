from flask import Flask, session, g, flash
from app.config import Config
from app.extensions.db import db
from app.extensions.login import login_manager
from app.extensions.migrate import migrate
from app.views.report_routes import report_bp
from app.views.site_routes import site_bp
from app.services.tenant_service import TenantService

# ...

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Inicializar Extensiones
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    
    from app.extensions.cache import cache
    cache.init_app(app)

    # Registrar Blueprints
    from app.models import core # Register core models
    from app.views.auth_routes import auth_bp
    from app.views.equipo_routes import equipo_bp
    from app.views.policy_routes import policy_bp
    from app.views.main_routes import main_bp
    from app.views.role_routes import role_bp
    from app.views.user_role_routes import user_role_bp
    from app.views.device_routes import device_bp
    from app.views.history_routes import history_bp
    from app.views.analyzer_routes import analyzer_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(role_bp)
    app.register_blueprint(user_role_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(equipo_bp)
    app.register_blueprint(policy_bp)
    app.register_blueprint(site_bp)
    app.register_blueprint(device_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(analyzer_bp)

    # Register API v1 Blueprint
    from app.api.v1 import api_v1_bp
    app.register_blueprint(api_v1_bp)

    @app.before_request
    def load_tenant_session():
        if 'company_id' in session:
            try:
                g.tenant_session = TenantService.get_session(session['company_id'])
                # Simple connectivity check
                g.tenant_session.execute(db.text("SELECT 1"))
            except Exception as e:
                app.logger.error(f"Failed to create tenant session: {e}")
                session.pop('company_id', None) # Clear invalid company
                flash("Error de conexión con la base de datos de la empresa. Por favor contacte soporte.", "danger")
                # Can't redirect easily in before_request without returning response object, 
                # but clearing session will force re-selection or logout on next request if handled by decorators.
    
    @app.teardown_request
    def close_tenant_session(exception=None):
        s = getattr(g, 'tenant_session', None)
        if s:
            s.close()

    return app
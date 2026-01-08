import uuid
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.extensions.db import db

class PolicyHistory(db.Model):
    __tablename__ = 'policy_history'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_uuid = db.Column(UUID(as_uuid=True), index=True, nullable=False) # Not FK to policies.id to allow history of deleted policies
    
    device_id = db.Column(UUID(as_uuid=True), db.ForeignKey('equipos.id'), nullable=False)
    vdom = db.Column(db.String(50), nullable=False, index=True)  # VDOM name for filtering
    vdom_id = db.Column(UUID(as_uuid=True), db.ForeignKey('vdoms.id'), nullable=True, index=True)  # v1.3.0 FK
    
    # Group changes from the same import session
    import_session_id = db.Column(UUID(as_uuid=True), nullable=True, index=True)
    
    change_date = db.Column(db.DateTime, default=db.func.now(), nullable=False)
    change_type = db.Column(db.String(20), nullable=False) # 'create', 'modify', 'delete'
    
    # Who made the change? (Optional, if import process knows)
    # user_id = db.Column(UUID(as_uuid=True), nullable=True) 

    delta = db.Column(JSONB) # The diff - detailed changes
    snapshot = db.Column(JSONB) # The full state AFTER the change (for recovery)

    def __repr__(self):
        return f"<PolicyHistory {self.policy_uuid} - {self.change_type}>"

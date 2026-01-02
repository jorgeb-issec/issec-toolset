import uuid
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.extensions.db import db

class ConfigHistory(db.Model):
    """Stores history of device configuration changes"""
    __tablename__ = 'config_history'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = db.Column(UUID(as_uuid=True), db.ForeignKey('equipos.id'), nullable=False)
    
    change_date = db.Column(db.DateTime, default=db.func.now(), nullable=False)
    change_type = db.Column(db.String(20), nullable=False)  # 'initial', 'update'
    
    # Store the full config at this point in time
    raw_config = db.Column(db.Text)  # Full .config file content
    config_data = db.Column(JSONB)   # Parsed config (interfaces, HA, etc.)
    
    # Summary of changes from previous version
    delta_summary = db.Column(JSONB)  # {interfaces_added: 5, interfaces_removed: 2, ha_changed: true, ...}
    
    # Optional: user who made the change
    # user_id = db.Column(UUID(as_uuid=True), nullable=True)

    def __repr__(self):
        return f"<ConfigHistory {self.device_id} - {self.change_type} @ {self.change_date}>"

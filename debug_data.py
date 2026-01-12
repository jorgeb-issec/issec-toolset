
import sys
import os
from app import create_app
from app.extensions.db import db
from app.models.log_entry import LogEntry
from app.models.equipo import Equipo
from flask import g

app = create_app()

with app.app_context():
    # We need to simulate a tenant session if relevant, but Equipo/Logs usually rely on correct schema
    # The LogEntry -> Equipo relationship is via device_id (central or tenant? usually tenant)
    
    # However, in this system, it seems to use `g.tenant_session`.
    # Let's try to access the default session or just raw SQL to check linkage.
    
    try:
        print("Checking Device <-> Log Counts:")
        
        # Get all devices
        devices = db.session.query(Equipo).all()
        print(f"Total Devices in Main DB: {len(devices)}")
        
        # Since LogEntry is in Tenant DB usually, but here we see usages of `g.tenant_session` in routes.
        # But for script, we might need to manually bind.
        # Let's check if LogEntry is in the default bound DB or if we need to switch schemas.
        # The verify_setup used default create_app.
        
        # Let's just try to query LogEntry from the session app uses.
        # If the app is single-tenant for now or uses public schema:
        
        log_counts = db.session.query(LogEntry.device_id, db.func.count(LogEntry.id)).group_by(LogEntry.device_id).all()
        
        print("\nLog Counts by Device ID (in LogEntry table):")
        if not log_counts:
             print("No logs found in default session. Trying to inspect schema...")
        
        device_map = {str(d.id): d.nombre for d in devices}
        
        for dev_id, count in log_counts:
            dev_name = device_map.get(str(dev_id), "UNKNOWN_DEVICE")
            print(f"Device: {dev_name} ({dev_id}) - Logs: {count}")
            
    except Exception as e:
        print(f"Error querying: {e}")
        import traceback
        traceback.print_exc()

#!/usr/bin/env python3
"""
Script to migrate policy_history table to add vdom and import_session_id columns
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.extensions.db import db
from app import create_app
from sqlalchemy import text

def run_migration():
    """Execute the migration to add new columns to policy_history"""
    app = create_app()
    
    with app.app_context():
        try:
            print("🔄 Starting migration: Add vdom and import_session_id to policy_history")
            print("-" * 60)
            
            # Check if columns already exist
            check_query = text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'policy_history' 
                AND column_name IN ('vdom', 'import_session_id')
            """)
            
            result = db.session.execute(check_query)
            existing_columns = [row[0] for row in result]
            
            if 'vdom' in existing_columns and 'import_session_id' in existing_columns:
                print("✅ Columns already exist. Migration not needed.")
                return
            
            print(f"📊 Existing columns: {existing_columns}")
            
            # Add vdom column if it doesn't exist
            if 'vdom' not in existing_columns:
                print("\n1️⃣ Adding 'vdom' column...")
                db.session.execute(text("""
                    ALTER TABLE policy_history 
                    ADD COLUMN vdom VARCHAR(50)
                """))
                db.session.commit()
                print("   ✅ Column 'vdom' added")
                
                # Set default values for existing records
                print("\n2️⃣ Setting default 'vdom' values for existing records...")
                db.session.execute(text("""
                    UPDATE policy_history 
                    SET vdom = 'root' 
                    WHERE vdom IS NULL
                """))
                db.session.commit()
                print("   ✅ Default values set")
                
                # Make vdom NOT NULL
                print("\n3️⃣ Making 'vdom' column NOT NULL...")
                db.session.execute(text("""
                    ALTER TABLE policy_history 
                    ALTER COLUMN vdom SET NOT NULL
                """))
                db.session.commit()
                print("   ✅ Column 'vdom' is now NOT NULL")
                
                # Create index
                print("\n4️⃣ Creating index on 'vdom'...")
                db.session.execute(text("""
                    CREATE INDEX IF NOT EXISTS ix_policy_history_vdom 
                    ON policy_history(vdom)
                """))
                db.session.commit()
                print("   ✅ Index created")
            
            # Add import_session_id column if it doesn't exist
            if 'import_session_id' not in existing_columns:
                print("\n5️⃣ Adding 'import_session_id' column...")
                db.session.execute(text("""
                    ALTER TABLE policy_history 
                    ADD COLUMN import_session_id UUID
                """))
                db.session.commit()
                print("   ✅ Column 'import_session_id' added")
                
                # Create index
                print("\n6️⃣ Creating index on 'import_session_id'...")
                db.session.execute(text("""
                    CREATE INDEX IF NOT EXISTS ix_policy_history_import_session_id 
                    ON policy_history(import_session_id)
                """))
                db.session.commit()
                print("   ✅ Index created")
            
            # Verify migration
            print("\n7️⃣ Verifying migration...")
            verify_query = text("""
                SELECT column_name, data_type, is_nullable 
                FROM information_schema.columns 
                WHERE table_name = 'policy_history' 
                ORDER BY ordinal_position
            """)
            
            result = db.session.execute(verify_query)
            print("\n📋 Current schema for policy_history:")
            print("-" * 60)
            for row in result:
                nullable = "NULL" if row[2] == 'YES' else "NOT NULL"
                print(f"   {row[0]:25s} {row[1]:15s} {nullable}")
            
            print("\n" + "=" * 60)
            print("✅ Migration completed successfully!")
            print("=" * 60)
            
        except Exception as e:
            print(f"\n❌ Error during migration: {str(e)}")
            db.session.rollback()
            import traceback
            traceback.print_exc()
            sys.exit(1)

if __name__ == '__main__':
    run_migration()

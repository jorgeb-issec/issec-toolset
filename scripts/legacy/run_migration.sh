#!/bin/bash
# Migration script to add vdom and import_session_id to policy_history

echo "🔄 Starting migration: Add vdom and import_session_id to policy_history"
echo "================================================================"

# Activate virtual environment
source .venv/bin/activate

# Run Python migration script
python3 migrate_history.py

echo ""
echo "================================================================"
echo "Migration script completed. Check output above for status."

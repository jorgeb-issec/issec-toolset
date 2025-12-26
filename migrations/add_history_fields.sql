-- Migration: Add vdom and import_session_id to policy_history table
-- Date: 2025-12-16

-- Add new columns
ALTER TABLE policy_history ADD COLUMN IF NOT EXISTS vdom VARCHAR(50);
ALTER TABLE policy_history ADD COLUMN IF NOT EXISTS import_session_id UUID;

-- Set default value for existing records
UPDATE policy_history SET vdom = 'root' WHERE vdom IS NULL;

-- Make vdom NOT NULL after setting defaults
ALTER TABLE policy_history ALTER COLUMN vdom SET NOT NULL;

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS ix_policy_history_vdom ON policy_history(vdom);
CREATE INDEX IF NOT EXISTS ix_policy_history_import_session_id ON policy_history(import_session_id);

-- Verify changes
SELECT column_name, data_type, is_nullable 
FROM information_schema.columns 
WHERE table_name = 'policy_history' 
ORDER BY ordinal_position;

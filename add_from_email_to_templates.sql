-- Add from_email column to email_templates table
-- This migration adds the from_email field for SMTP email selection

-- Add from_email column if it doesn't exist
ALTER TABLE "email_templates" 
ADD COLUMN IF NOT EXISTS "from_email" VARCHAR(255);

-- Add comment
COMMENT ON COLUMN "email_templates"."from_email" IS 'Email address to use when sending emails with this template. If null, uses default SMTP settings.';

-- Create email_templates table to store custom email templates
CREATE TABLE IF NOT EXISTS "email_templates" (
    "id" SERIAL PRIMARY KEY,
    "name" VARCHAR(255) UNIQUE NOT NULL,
    "description" TEXT,
    "html_code" TEXT NOT NULL,
    "variables" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "is_default" BOOLEAN DEFAULT false,
    "preview_image_url" VARCHAR(500),
    "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    "created_by" VARCHAR(255)
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS "idx_email_templates_name" ON "email_templates"("name");
CREATE INDEX IF NOT EXISTS "idx_email_templates_is_default" ON "email_templates"("is_default");
CREATE INDEX IF NOT EXISTS "idx_email_templates_created_at" ON "email_templates"("created_at");
CREATE INDEX IF NOT EXISTS "idx_email_templates_created_by" ON "email_templates"("created_by");

-- Add comment to table
COMMENT ON TABLE "email_templates" IS 'Stores custom email templates with variable support for email sending';

-- Ensure only one default template exists (enforced at application level)
-- Create a unique partial index to ensure only one default template
CREATE UNIQUE INDEX IF NOT EXISTS "idx_email_templates_unique_default" 
ON "email_templates"("is_default") 
WHERE "is_default" = true;


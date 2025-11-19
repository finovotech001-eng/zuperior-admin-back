-- Create sent_emails table to record all sent custom emails
CREATE TABLE IF NOT EXISTS "sent_emails" (
    "id" SERIAL PRIMARY KEY,
    "recipient_email" VARCHAR(255) NOT NULL,
    "recipient_name" VARCHAR(255),
    "subject" TEXT NOT NULL,
    "content_body" TEXT NOT NULL,
    "is_html" BOOLEAN DEFAULT true,
    "recipient_type" VARCHAR(50),
    "status" VARCHAR(20) DEFAULT 'pending',
    "error_message" TEXT,
    "sent_at" TIMESTAMP,
    "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    "admin_id" VARCHAR(255),
    "attachments_count" INTEGER DEFAULT 0
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS "idx_sent_emails_recipient_email" ON "sent_emails"("recipient_email");
CREATE INDEX IF NOT EXISTS "idx_sent_emails_status" ON "sent_emails"("status");
CREATE INDEX IF NOT EXISTS "idx_sent_emails_sent_at" ON "sent_emails"("sent_at");
CREATE INDEX IF NOT EXISTS "idx_sent_emails_created_at" ON "sent_emails"("created_at");
CREATE INDEX IF NOT EXISTS "idx_sent_emails_admin_id" ON "sent_emails"("admin_id");
CREATE INDEX IF NOT EXISTS "idx_sent_emails_recipient_type" ON "sent_emails"("recipient_type");

-- Add comment to table
COMMENT ON TABLE "sent_emails" IS 'Records all custom emails sent through the admin panel';


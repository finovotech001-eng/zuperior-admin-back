-- SQL Migration for group_management table
-- Run this query in your PostgreSQL database

CREATE TABLE IF NOT EXISTS "group_management" (
    "id" SERIAL PRIMARY KEY,
    "group" VARCHAR(255) UNIQUE NOT NULL,
    "dedicated_name" VARCHAR(255),
    "server" INTEGER DEFAULT 1,
    "permissions_flags" INTEGER DEFAULT 0,
    "auth_mode" INTEGER DEFAULT 0,
    "auth_password_min" INTEGER DEFAULT 8,
    "company" VARCHAR(255),
    "company_page" VARCHAR(255),
    "company_email" VARCHAR(255),
    "company_support_page" VARCHAR(500),
    "company_support_email" VARCHAR(255),
    "company_catalog" VARCHAR(255),
    "currency" VARCHAR(10),
    "currency_digits" INTEGER DEFAULT 2,
    "reports_mode" INTEGER DEFAULT 1,
    "reports_flags" INTEGER DEFAULT 5,
    "reports_smtp" VARCHAR(255),
    "reports_smtp_login" VARCHAR(255),
    "news_mode" INTEGER DEFAULT 2,
    "news_category" VARCHAR(255),
    "mail_mode" INTEGER DEFAULT 1,
    "trade_flags" INTEGER DEFAULT 2135,
    "trade_interestrate" DECIMAL(10, 2) DEFAULT 0,
    "trade_virtual_credit" DECIMAL(10, 2) DEFAULT 0,
    "margin_free_mode" INTEGER DEFAULT 1,
    "margin_so_mode" INTEGER DEFAULT 0,
    "margin_call" DECIMAL(10, 2) DEFAULT 100,
    "margin_stop_out" DECIMAL(10, 2) DEFAULT 5,
    "demo_leverage" INTEGER DEFAULT 100,
    "demo_deposit" DECIMAL(10, 2) DEFAULT 0,
    "limit_history" INTEGER DEFAULT 0,
    "limit_orders" INTEGER DEFAULT 0,
    "limit_symbols" INTEGER DEFAULT 0,
    "limit_positions" INTEGER DEFAULT 0,
    "margin_mode" INTEGER DEFAULT 2,
    "margin_flags" INTEGER DEFAULT 0,
    "trade_transfer_mode" INTEGER DEFAULT 0,
    "is_active" BOOLEAN DEFAULT true,
    "synced_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ(6) DEFAULT NOW()
);

-- Create indexes
CREATE INDEX IF NOT EXISTS "group_management_group_idx" ON "group_management"("group");
CREATE INDEX IF NOT EXISTS "group_management_is_active_idx" ON "group_management"("is_active");
CREATE INDEX IF NOT EXISTS "group_management_server_idx" ON "group_management"("server");


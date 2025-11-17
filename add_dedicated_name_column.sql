-- SQL ALTER statement to add dedicated_name column to group_management table
-- Run this query in your PostgreSQL database

ALTER TABLE "group_management" 
ADD COLUMN IF NOT EXISTS "dedicated_name" VARCHAR(255);

-- Optional: Add an index if you plan to search by dedicated_name frequently
-- CREATE INDEX IF NOT EXISTS "group_management_dedicated_name_idx" ON "group_management"("dedicated_name");


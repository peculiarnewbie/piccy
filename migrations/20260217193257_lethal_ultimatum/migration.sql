ALTER TABLE `uploads` ADD `owner_anon_id` text;--> statement-breakpoint
CREATE INDEX `idx_uploads_owner_anon_created` ON `uploads` (`owner_anon_id`,`created_at`);
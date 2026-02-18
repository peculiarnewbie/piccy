PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_upload_copy_events` (
	`id` text PRIMARY KEY,
	`upload_id` text NOT NULL,
	`actor_user_id` text,
	`copied_format` text NOT NULL,
	`copied_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`source` text NOT NULL,
	CONSTRAINT `fk_upload_copy_events_upload_id_uploads_id_fk` FOREIGN KEY (`upload_id`) REFERENCES `uploads`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
INSERT INTO `__new_upload_copy_events`(`id`, `upload_id`, `actor_user_id`, `copied_format`, `copied_at`, `source`) SELECT `id`, `upload_id`, `actor_user_id`, `copied_format`, `copied_at`, `source` FROM `upload_copy_events`;--> statement-breakpoint
DROP TABLE `upload_copy_events`;--> statement-breakpoint
ALTER TABLE `__new_upload_copy_events` RENAME TO `upload_copy_events`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_uploads` (
	`id` text PRIMARY KEY,
	`owner_user_id` text,
	`owner_anon_id` text,
	`expires_at` text,
	`r2_key` text NOT NULL,
	`public_url` text NOT NULL,
	`mime_type` text NOT NULL,
	`size_bytes` integer NOT NULL,
	`thumb_r2_key` text,
	`webp_r2_key` text,
	`webp_size_bytes` integer,
	`optimization_status` text DEFAULT 'pending' NOT NULL,
	`optimized_at` text,
	`width` integer,
	`height` integer,
	`sha256` text,
	`copy_count` integer DEFAULT 0 NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`deleted_at` text
);
--> statement-breakpoint
INSERT INTO `__new_uploads`(`id`, `owner_user_id`, `owner_anon_id`, `expires_at`, `r2_key`, `public_url`, `mime_type`, `size_bytes`, `thumb_r2_key`, `webp_r2_key`, `webp_size_bytes`, `optimization_status`, `optimized_at`, `width`, `height`, `sha256`, `copy_count`, `created_at`, `updated_at`, `deleted_at`) SELECT `id`, `owner_user_id`, `owner_anon_id`, `expires_at`, `r2_key`, `public_url`, `mime_type`, `size_bytes`, `thumb_r2_key`, `webp_r2_key`, `webp_size_bytes`, `optimization_status`, `optimized_at`, `width`, `height`, `sha256`, `copy_count`, `created_at`, `updated_at`, `deleted_at` FROM `uploads`;--> statement-breakpoint
DROP TABLE `uploads`;--> statement-breakpoint
ALTER TABLE `__new_uploads` RENAME TO `uploads`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
CREATE INDEX `idx_upload_copy_events_upload_copied_at` ON `upload_copy_events` (`upload_id`,`copied_at`);--> statement-breakpoint
CREATE UNIQUE INDEX `uploads_r2_key_unique` ON `uploads` (`r2_key`);--> statement-breakpoint
CREATE INDEX `idx_uploads_owner_created` ON `uploads` (`owner_user_id`,`created_at`);--> statement-breakpoint
CREATE INDEX `idx_uploads_owner_anon_created` ON `uploads` (`owner_anon_id`,`created_at`);--> statement-breakpoint
CREATE INDEX `idx_uploads_created` ON `uploads` (`created_at`);--> statement-breakpoint
CREATE INDEX `idx_uploads_expires_at` ON `uploads` (`expires_at`) WHERE "uploads"."expires_at" IS NOT NULL;
CREATE TABLE `account` (
	`id` text PRIMARY KEY,
	`accountId` text NOT NULL,
	`providerId` text NOT NULL,
	`userId` text NOT NULL,
	`accessToken` text,
	`refreshToken` text,
	`idToken` text,
	`accessTokenExpiresAt` integer,
	`refreshTokenExpiresAt` integer,
	`scope` text,
	`password` text,
	`createdAt` integer NOT NULL,
	`updatedAt` integer NOT NULL,
	CONSTRAINT `fk_account_userId_user_id_fk` FOREIGN KEY (`userId`) REFERENCES `user`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `session` (
	`id` text PRIMARY KEY,
	`expiresAt` integer NOT NULL,
	`token` text NOT NULL UNIQUE,
	`createdAt` integer NOT NULL,
	`updatedAt` integer NOT NULL,
	`ipAddress` text,
	`userAgent` text,
	`userId` text NOT NULL,
	CONSTRAINT `fk_session_userId_user_id_fk` FOREIGN KEY (`userId`) REFERENCES `user`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `user` (
	`id` text PRIMARY KEY,
	`name` text NOT NULL,
	`email` text NOT NULL UNIQUE,
	`emailVerified` integer NOT NULL,
	`image` text,
	`createdAt` integer NOT NULL,
	`updatedAt` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `verification` (
	`id` text PRIMARY KEY,
	`identifier` text NOT NULL,
	`value` text NOT NULL,
	`expiresAt` integer NOT NULL,
	`createdAt` integer NOT NULL,
	`updatedAt` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `request_rate_limits` (
	`id` text PRIMARY KEY,
	`operation` text NOT NULL,
	`scope` text NOT NULL,
	`scope_id` text NOT NULL,
	`window_started_at` integer NOT NULL,
	`request_count` integer DEFAULT 1 NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE TABLE `upload_copy_events` (
	`id` text PRIMARY KEY,
	`upload_id` text NOT NULL,
	`actor_user_id` text,
	`copied_format` text NOT NULL,
	`copied_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`source` text NOT NULL,
	CONSTRAINT `fk_upload_copy_events_upload_id_uploads_id_fk` FOREIGN KEY (`upload_id`) REFERENCES `uploads`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `uploads` (
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
CREATE INDEX `account_userId_idx` ON `account` (`userId`);--> statement-breakpoint
CREATE UNIQUE INDEX `account_provider_account_unique` ON `account` (`providerId`,`accountId`);--> statement-breakpoint
CREATE INDEX `session_userId_idx` ON `session` (`userId`);--> statement-breakpoint
CREATE INDEX `verification_identifier_idx` ON `verification` (`identifier`);--> statement-breakpoint
CREATE INDEX `idx_request_rate_limits_operation_scope` ON `request_rate_limits` (`operation`,`scope`,`window_started_at`);--> statement-breakpoint
CREATE INDEX `idx_request_rate_limits_window_started_at` ON `request_rate_limits` (`window_started_at`);--> statement-breakpoint
CREATE INDEX `idx_upload_copy_events_upload_copied_at` ON `upload_copy_events` (`upload_id`,`copied_at`);--> statement-breakpoint
CREATE UNIQUE INDEX `uploads_r2_key_unique` ON `uploads` (`r2_key`);--> statement-breakpoint
CREATE INDEX `idx_uploads_owner_created` ON `uploads` (`owner_user_id`,`created_at`);--> statement-breakpoint
CREATE INDEX `idx_uploads_owner_anon_created` ON `uploads` (`owner_anon_id`,`created_at`);--> statement-breakpoint
CREATE INDEX `idx_uploads_created` ON `uploads` (`created_at`);--> statement-breakpoint
CREATE INDEX `idx_uploads_expires_at` ON `uploads` (`expires_at`) WHERE "uploads"."expires_at" IS NOT NULL;
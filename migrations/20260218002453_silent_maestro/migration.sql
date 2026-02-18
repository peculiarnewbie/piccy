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
CREATE TABLE `request_telemetry_events` (
	`id` text PRIMARY KEY,
	`request_type` text NOT NULL,
	`request_path` text NOT NULL,
	`status_code` integer NOT NULL,
	`latency_ms` integer NOT NULL,
	`failed` integer DEFAULT false NOT NULL,
	`failure_reason` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_request_rate_limits_operation_scope` ON `request_rate_limits` (`operation`,`scope`,`window_started_at`);--> statement-breakpoint
CREATE INDEX `idx_request_rate_limits_window_started_at` ON `request_rate_limits` (`window_started_at`);--> statement-breakpoint
CREATE INDEX `idx_request_telemetry_type_created_at` ON `request_telemetry_events` (`request_type`,`created_at`);--> statement-breakpoint
CREATE INDEX `idx_request_telemetry_status_created_at` ON `request_telemetry_events` (`status_code`,`created_at`);
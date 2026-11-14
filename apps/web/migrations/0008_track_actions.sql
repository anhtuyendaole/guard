CREATE TABLE `track_integration` (
	`organization_id` text PRIMARY KEY NOT NULL,
	`address` text NOT NULL,
	`workspace_slug` text NOT NULL,
	`team_key` text NOT NULL,
	`fix_label` text,
	`key_sealed` text NOT NULL,
	`key_hint` text NOT NULL,
	`added_by` text NOT NULL,
	`added_at` integer NOT NULL,
	`last_check_at` integer,
	`last_check_outcome` text,
	FOREIGN KEY (`organization_id`) REFERENCES `organization`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
ALTER TABLE `finding` ADD `track_state` text;--> statement-breakpoint
ALTER TABLE `finding` ADD `track_issue_key` text;--> statement-breakpoint
ALTER TABLE `finding` ADD `track_issue_url` text;--> statement-breakpoint
ALTER TABLE `finding` ADD `track_filed_at` integer;--> statement-breakpoint
ALTER TABLE `finding` ADD `track_filed_by` text;--> statement-breakpoint
ALTER TABLE `finding` ADD `fix_requested_at` integer;
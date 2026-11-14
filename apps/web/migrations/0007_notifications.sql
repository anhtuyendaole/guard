CREATE TABLE `notification_log` (
	`organization_id` text NOT NULL,
	`kind` text NOT NULL,
	`period` text NOT NULL,
	`sent_at` integer NOT NULL,
	PRIMARY KEY(`organization_id`, `kind`, `period`),
	FOREIGN KEY (`organization_id`) REFERENCES `organization`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "notification_log_kind" CHECK("notification_log"."kind" IN ('alert', 'digest'))
);
--> statement-breakpoint
CREATE TABLE `notification_preference` (
	`organization_id` text NOT NULL,
	`user_id` text NOT NULL,
	`alert_email` integer,
	`digest_email` integer,
	`findings_seen_at` integer,
	PRIMARY KEY(`organization_id`, `user_id`),
	FOREIGN KEY (`organization_id`) REFERENCES `organization`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "notification_preference_switches" CHECK(("notification_preference"."alert_email" IS NULL OR "notification_preference"."alert_email" IN (0, 1)) AND ("notification_preference"."digest_email" IS NULL OR "notification_preference"."digest_email" IN (0, 1)))
);
--> statement-breakpoint
CREATE INDEX `notification_preference_user_idx` ON `notification_preference` (`user_id`);--> statement-breakpoint
ALTER TABLE `finding` ADD `raised_at` integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `finding` ADD `notified_at` integer;
--> statement-breakpoint
-- What exists now is not news: findings count as raised and told when first seen, and each member
-- starts with Findings opened just now, so that a deployment's update does not light every badge or
-- send an alert for what the workspace already knew.
UPDATE `finding` SET `raised_at` = `first_seen_at`, `notified_at` = `first_seen_at`;--> statement-breakpoint
INSERT INTO `notification_preference` (`organization_id`, `user_id`, `findings_seen_at`)
SELECT `organization_id`, `user_id`, CAST(strftime('%s', 'now') AS integer) * 1000 FROM `member`;

CREATE TABLE `traffic_count` (
	`connection_id` text NOT NULL,
	`organization_id` text NOT NULL,
	`zone_id` text NOT NULL,
	`day` text NOT NULL,
	`dimension` text NOT NULL,
	`key` text NOT NULL,
	`action` text DEFAULT '' NOT NULL,
	`source` text DEFAULT '' NOT NULL,
	`description` text,
	`partial` integer DEFAULT 0 NOT NULL,
	`count` integer NOT NULL,
	PRIMARY KEY(`connection_id`, `zone_id`, `day`, `dimension`, `key`, `action`, `source`),
	FOREIGN KEY (`connection_id`) REFERENCES `connection`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`organization_id`) REFERENCES `organization`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "traffic_count_dimension" CHECK("traffic_count"."dimension" IN ('action', 'country', 'host', 'rule')),
	CONSTRAINT "traffic_count_count" CHECK("traffic_count"."count" >= 0)
);
--> statement-breakpoint
CREATE INDEX `traffic_count_org_idx` ON `traffic_count` (`organization_id`,`zone_id`,`day`);--> statement-breakpoint
CREATE TABLE `traffic_zone` (
	`connection_id` text NOT NULL,
	`organization_id` text NOT NULL,
	`zone_id` text NOT NULL,
	`name` text NOT NULL,
	`plan` text,
	`first_day` text,
	`last_day` text,
	`last_failure` text,
	`seen_at` integer NOT NULL,
	PRIMARY KEY(`connection_id`, `zone_id`),
	FOREIGN KEY (`connection_id`) REFERENCES `connection`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`organization_id`) REFERENCES `organization`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `traffic_zone_org_idx` ON `traffic_zone` (`organization_id`);--> statement-breakpoint
ALTER TABLE `connection` ADD `traffic_outcome` text;
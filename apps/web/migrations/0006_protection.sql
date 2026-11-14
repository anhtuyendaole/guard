CREATE TABLE `protection_rule` (
	`connection_id` text NOT NULL,
	`organization_id` text NOT NULL,
	`zone_id` text NOT NULL,
	`rule_id` text NOT NULL,
	`position` integer NOT NULL,
	`action` text NOT NULL,
	`description` text NOT NULL,
	`enabled` integer NOT NULL,
	`last_updated` text,
	PRIMARY KEY(`connection_id`, `zone_id`, `rule_id`),
	FOREIGN KEY (`connection_id`) REFERENCES `connection`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`organization_id`) REFERENCES `organization`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `protection_rule_org_idx` ON `protection_rule` (`organization_id`,`zone_id`);--> statement-breakpoint
CREATE TABLE `protection_zone` (
	`connection_id` text NOT NULL,
	`organization_id` text NOT NULL,
	`zone_id` text NOT NULL,
	`name` text NOT NULL,
	`plan` text,
	`read_at` integer NOT NULL,
	`custom_state` text NOT NULL,
	`custom_failure` text,
	`managed_state` text NOT NULL,
	`managed_failure` text,
	`managed_rulesets` text,
	`rate_limit_state` text NOT NULL,
	`rate_limit_failure` text,
	`rate_limit_total` integer,
	`rate_limit_enabled` integer,
	`bot_state` text NOT NULL,
	`bot_failure` text,
	`bot_fight_mode` integer,
	`security_level_state` text NOT NULL,
	`security_level_failure` text,
	`security_level` text,
	PRIMARY KEY(`connection_id`, `zone_id`),
	FOREIGN KEY (`connection_id`) REFERENCES `connection`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`organization_id`) REFERENCES `organization`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "protection_zone_custom_state" CHECK(custom_state IN ('ok', 'none', 'failed')),
	CONSTRAINT "protection_zone_managed_state" CHECK(managed_state IN ('ok', 'none', 'failed')),
	CONSTRAINT "protection_zone_rate_limit_state" CHECK(rate_limit_state IN ('ok', 'none', 'failed')),
	CONSTRAINT "protection_zone_bot_state" CHECK(bot_state IN ('ok', 'none', 'failed')),
	CONSTRAINT "protection_zone_security_level_state" CHECK(security_level_state IN ('ok', 'none', 'failed'))
);
--> statement-breakpoint
CREATE INDEX `protection_zone_org_idx` ON `protection_zone` (`organization_id`);
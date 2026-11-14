import { sql } from "drizzle-orm";
import {
	check,
	index,
	integer,
	primaryKey,
	sqliteTable,
	text,
	uniqueIndex,
} from "drizzle-orm/sqlite-core";
import { organization } from "./auth-schema";

/** How many connections one workspace may have. The trigger `connection_is_capped` holds it. */
export const MAX_CONNECTIONS = 50;
/** How many scans a connection keeps. */
export const KEPT_SCANS = 30;
/** The longest reason an admin gives for dismissing a finding. */
export const MAX_DISMISS_REASON = 200;

export const CONNECTION_KINDS = ["cloudflare", "github"] as const;
export type ConnectionKind = (typeof CONNECTION_KINDS)[number];

export const SEVERITIES = ["critical", "high", "moderate", "low", "unknown"] as const;
export type FindingSeverity = (typeof SEVERITIES)[number];

/** How many days of traffic a connection keeps; the scan deletes older ones. */
export const KEPT_TRAFFIC_DAYS = 90;

export const TRAFFIC_DIMENSIONS = ["action", "country", "host", "rule"] as const;
export type TrafficDimension = (typeof TRAFFIC_DIMENSIONS)[number];

export const FINDING_SOURCES = ["cloudflare", "dependency"] as const;
export type FindingSource = (typeof FINDING_SOURCES)[number];

/**
 * "Connections" in docs/architecture.md: a Cloudflare account or a GitHub repository a workspace
 * lets Guard read. The token is sealed (`secrets.ts`), opened only inside a scan or a check, and
 * pages see its last four characters.
 */
export const connection = sqliteTable(
	"connection",
	{
		id: text("id").primaryKey(),
		organizationId: text("organization_id")
			.notNull()
			.references(() => organization.id, { onDelete: "cascade" }),
		kind: text("kind", { enum: CONNECTION_KINDS }).notNull(),
		/** A Cloudflare account id, or `owner/name` as GitHub writes it. */
		target: text("target").notNull(),
		/** GitHub's id of the repository, which a rename keeps. Null for Cloudflare. */
		githubRepositoryId: integer("github_repository_id"),
		/** What pages call it. */
		name: text("name").notNull(),
		tokenSealed: text("token_sealed").notNull(),
		/** The token's last four characters. */
		tokenHint: text("token_hint").notNull(),
		/** The admin's user id. Not a foreign key: the connection outlives their account. */
		addedBy: text("added_by").notNull(),
		addedAt: integer("added_at", { mode: "timestamp_ms" }).notNull(),
		lastScanAt: integer("last_scan_at", { mode: "timestamp_ms" }),
		/** `ok`, a failure kind of `UpstreamFailure`, or `unreadable` for a token that does not open. */
		lastScanOutcome: text("last_scan_outcome"),
		nextScanAt: integer("next_scan_at", { mode: "timestamp_ms" }).notNull(),
		/** Set while a scan runs, so that one connection is never scanned twice at once. */
		scanStartedAt: integer("scan_started_at", { mode: "timestamp_ms" }),
		/**
		 * How the last read of WAF and bot traffic went, for a Cloudflare connection: `ok`, or a failure
		 * kind of `UpstreamFailure`. It is kept apart from `last_scan_outcome` so that a token without
		 * Analytics › Read still has its Security Insights scanned. Null until a scan has run.
		 */
		trafficOutcome: text("traffic_outcome"),
	},
	(table) => [
		uniqueIndex("connection_target_unique").on(table.organizationId, table.kind, table.target),
		uniqueIndex("connection_repository_unique").on(table.organizationId, table.githubRepositoryId),
		index("connection_next_scan_idx").on(table.nextScanAt),
		check("connection_kind", sql`${table.kind} IN ('cloudflare', 'github')`),
		check(
			"connection_repository_id",
			sql`(${table.kind} = 'github') = (${table.githubRepositoryId} IS NOT NULL)`,
		),
	],
);

/**
 * One problem a scan found, kept by its fingerprint so that a rescan updates it, closes it when it
 * is gone and reopens it when it comes back. It holds what a page shows and nothing of what was
 * read: no insight payloads and no lockfile contents.
 */
export const finding = sqliteTable(
	"finding",
	{
		id: text("id").primaryKey(),
		organizationId: text("organization_id")
			.notNull()
			.references(() => organization.id, { onDelete: "cascade" }),
		connectionId: text("connection_id")
			.notNull()
			.references(() => connection.id, { onDelete: "cascade" }),
		fingerprint: text("fingerprint").notNull(),
		source: text("source", { enum: FINDING_SOURCES }).notNull(),
		severity: text("severity", { enum: SEVERITIES }).notNull(),
		/** An insight's `issue_class`, or an advisory's id. */
		kind: text("kind").notNull(),
		/** A hostname or zone, or `package@versions in lockfile`. */
		subject: text("subject").notNull(),
		title: text("title").notNull(),
		/** The Cloudflare dashboard, or the advisory on osv.dev. */
		url: text("url").notNull(),
		fixedVersion: text("fixed_version"),
		firstSeenAt: integer("first_seen_at", { mode: "timestamp_ms" }).notNull(),
		lastSeenAt: integer("last_seen_at", { mode: "timestamp_ms" }).notNull(),
		/** Null while the problem is open. */
		resolvedAt: integer("resolved_at", { mode: "timestamp_ms" }),
		dismissedAt: integer("dismissed_at", { mode: "timestamp_ms" }),
		/** An admin's user id. Not a foreign key, as `connection.added_by`. */
		dismissedBy: text("dismissed_by"),
		dismissReason: text("dismiss_reason"),
	},
	(table) => [
		uniqueIndex("finding_fingerprint_unique").on(table.organizationId, table.fingerprint),
		index("finding_connection_idx").on(table.connectionId),
		index("finding_open_idx").on(table.organizationId, table.resolvedAt),
		check("finding_source", sql`${table.source} IN ('cloudflare', 'dependency')`),
		check(
			"finding_severity",
			sql`${table.severity} IN ('critical', 'high', 'moderate', 'low', 'unknown')`,
		),
		check(
			"finding_dismiss_reason",
			sql`${table.dismissReason} IS NULL OR length(${table.dismissReason}) <= ${sql.raw(String(MAX_DISMISS_REASON))}`,
		),
	],
);

/** What each scan did, for the page's last line about a connection. The last 30 are kept. */
export const scan = sqliteTable(
	"scan",
	{
		id: text("id").primaryKey(),
		connectionId: text("connection_id")
			.notNull()
			.references(() => connection.id, { onDelete: "cascade" }),
		startedAt: integer("started_at", { mode: "timestamp_ms" }).notNull(),
		finishedAt: integer("finished_at", { mode: "timestamp_ms" }).notNull(),
		outcome: text("outcome").notNull(),
		found: integer("found").notNull().default(0),
		added: integer("new").notNull().default(0),
		resolved: integer("resolved").notNull().default(0),
	},
	(table) => [index("scan_connection_idx").on(table.connectionId, table.startedAt)],
);

/**
 * The zones a Cloudflare connection last saw, and how far Guard has read each. Only active zones
 * are kept. Removing the connection removes them.
 */
export const trafficZone = sqliteTable(
	"traffic_zone",
	{
		connectionId: text("connection_id")
			.notNull()
			.references(() => connection.id, { onDelete: "cascade" }),
		organizationId: text("organization_id")
			.notNull()
			.references(() => organization.id, { onDelete: "cascade" }),
		zoneId: text("zone_id").notNull(),
		name: text("name").notNull(),
		plan: text("plan"),
		/**
		 * `first_day` and `last_day` bound a contiguous run of complete UTC days (`YYYY-MM-DD`) Guard
		 * has read, whether or not anything was acted on in them: a day in the run with no rows had
		 * nothing acted on, and counts as 0. A gap (a long pause, a failing token) starts a new run, so
		 * unread days are never zeros. Retention may delete counts older than `first_day`'s age; the
		 * spike rule looks back 8 days only, so `first_day` may stay older than the oldest stored row.
		 */
		firstDay: text("first_day"),
		lastDay: text("last_day"),
		/** Why this zone's last read failed, a failure kind; null when it went well. */
		lastFailure: text("last_failure"),
		seenAt: integer("seen_at", { mode: "timestamp_ms" }).notNull(),
	},
	(table) => [
		primaryKey({ columns: [table.connectionId, table.zoneId] }),
		index("traffic_zone_org_idx").on(table.organizationId),
	],
);

/**
 * What the WAF and bot features did to a zone's requests on one UTC day: counts and nothing that
 * names a visitor. Never an address, a user agent, a path, a query, a ray id or an ASN
 * (invariant 3). Host names are those of the customer's own zones. A `rule` row is an estimate
 * from sampled events.
 *
 * What `key` means depends on the dimension: `action` rows have the action as key (it is in
 * `action` too) and the security feature in `source`; `country` and `host` rows have the name as
 * key and the action in `action`; `rule` rows have the rule id as key, with its action, source and
 * description.
 */
export const trafficCount = sqliteTable(
	"traffic_count",
	{
		connectionId: text("connection_id")
			.notNull()
			.references(() => connection.id, { onDelete: "cascade" }),
		organizationId: text("organization_id")
			.notNull()
			.references(() => organization.id, { onDelete: "cascade" }),
		zoneId: text("zone_id").notNull(),
		/** `YYYY-MM-DD`, UTC. */
		day: text("day").notNull(),
		dimension: text("dimension", { enum: TRAFFIC_DIMENSIONS }).notNull(),
		key: text("key").notNull(),
		action: text("action").notNull().default(""),
		source: text("source").notNull().default(""),
		/** A rule's description, as its owner wrote it. */
		description: text("description"),
		/** For a rule: the day's events were cut short, so this counts a part of the day. */
		partial: integer("partial").notNull().default(0),
		count: integer("count").notNull(),
	},
	(table) => [
		primaryKey({
			columns: [
				table.connectionId,
				table.zoneId,
				table.day,
				table.dimension,
				table.key,
				table.action,
				table.source,
			],
		}),
		index("traffic_count_org_idx").on(table.organizationId, table.zoneId, table.day),
		check(
			"traffic_count_dimension",
			sql`${table.dimension} IN ('action', 'country', 'host', 'rule')`,
		),
		check("traffic_count_count", sql`${table.count} >= 0`),
	],
);

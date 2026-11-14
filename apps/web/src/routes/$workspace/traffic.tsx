import { createFileRoute, Link, notFound } from "@tanstack/react-router";
import { Button } from "#/components/ui/button";
import { useWorkspace } from "#/components/workspace/context";
import { Notice } from "#/components/workspace/notice";
import { TrafficChart } from "#/components/workspace/traffic-chart";
import {
	getTraffic,
	type TrafficConnectionView,
	type TrafficNameView,
	type TrafficRuleView,
	type TrafficZoneView,
} from "#/lib/connections";
import { formatUtcDay } from "#/lib/dates";
import { formatNumber } from "#/lib/numbers";
import { useDocumentTitle } from "#/lib/title";

/** Everything this screen says, in one place, so it can be translated without hunting for it. */
const TEXT = {
	title: "Traffic",
	intro:
		"Requests Cloudflare's WAF and bot features stopped or challenged, counted per zone and UTC day. Guard keeps counts only, never who sent a request or what it asked for.",
	empty: "No Cloudflare account connected.",
	hint: "Connect one to see what its zones' WAF and bot features did.",
	toConnections: "Connections",
	missing: "Page not found",
	missingHint: "Check the address, or go back to your workspace.",
	noZones: "Guard has not listed this account's zones yet.",
	noZonesFailed: (why: string) => `Guard could not read this account's traffic. ${why}`,
	notScanned: "Not scanned yet. The next scan reads this zone's recent days.",
	noEvents: "Nothing was stopped or challenged in the days Guard has read.",
	failure: {
		forbidden: "The token cannot read this traffic. It needs Zone › Analytics › Read on all zones.",
		unauthorized: "Cloudflare refused the token. It may have been revoked or have expired.",
		not_found: "Cloudflare did not show this zone to the token.",
		rate_limited: "Cloudflare was limiting requests. Guard tries again within the hour.",
		unavailable: "Cloudflare could not be reached. Guard tries again within the hour.",
		invalid_response: "Cloudflare answered in a way Guard does not understand.",
	} as Record<string, string>,
	failureOther: "Guard could not read this zone's traffic.",
	connection: (name: string) => `From ${name}`,
	plan: (name: string) => `Plan: ${name}`,
	chartHeading: "Stopped or challenged requests per day",
	chartSummary: (
		days: number,
		unread: number,
		first: string,
		last: string,
		total: string,
		peak: string,
		peakDay: string,
	) =>
		`Stopped or challenged requests per day, ${first} to ${last} (${days} days${unread > 0 ? `, ${unread} not read yet` : ""}): ${peak === "0" ? "none on the days read" : `${total} in all, at most ${peak} on ${peakDay}`}.`,
	weekHeading: "This week against last week",
	weekPart: (label: string, sum: string, read: number, of: number) =>
		read === 0
			? `No data for ${label}`
			: read === of
				? `${sum} ${label}`
				: `${sum} ${label} (${read} of ${of} days read)`,
	weekChange: (percent: number) =>
		`${percent > 0 ? "+" : percent < 0 ? "−" : ""}${Math.abs(percent)}% on last week`,
	rulesHeading: "Top rules yesterday",
	rulesNone: "No rule events for yesterday.",
	countriesHeading: "Top countries, last 7 days",
	hostsHeading: "Top hosts, last 7 days",
	none: "None.",
	sampled: "sampled",
	partial: "partial",
	sampledHint: "An estimate from sampled events.",
	partialHint: "An estimate from sampled events, cut short: part of the day is missing.",
	ruleOf: (action: string, source: string) => (source ? `${action} · ${source}` : action),
	noDescription: "No description",
};

export const Route = createFileRoute("/$workspace/traffic")({
	loader: async ({ params }) => {
		const page = await getTraffic({ data: params.workspace });
		if (!page) throw notFound();
		return page;
	},
	component: TrafficPage,
	notFoundComponent: () => <Notice title={TEXT.missing}>{TEXT.missingHint}</Notice>,
});

function TrafficPage() {
	useDocumentTitle(TEXT.title);
	const page = Route.useLoaderData();
	const { slug } = useWorkspace();

	if (!page.hasConnections) {
		return (
			<div className="mx-auto max-w-4xl space-y-6 px-4 py-10 sm:px-6">
				<h1 className="text-xl font-semibold tracking-tight">{TEXT.title}</h1>
				<Notice
					title={TEXT.empty}
					action={
						<Button asChild variant="outline">
							<Link to="/$workspace/connections" params={{ workspace: slug }}>
								{TEXT.toConnections}
							</Link>
						</Button>
					}
				>
					{TEXT.hint}
				</Notice>
			</div>
		);
	}

	return (
		<div className="mx-auto max-w-4xl space-y-6 px-4 py-10 sm:px-6">
			<div className="space-y-1">
				<h1 className="text-xl font-semibold tracking-tight">{TEXT.title}</h1>
				<p className="text-sm text-muted-foreground">{TEXT.intro}</p>
			</div>
			{page.connections.map((connection) => (
				<ConnectionTraffic key={connection.id} connection={connection} />
			))}
		</div>
	);
}

function failureText(failure: string | null): string {
	return (failure && TEXT.failure[failure]) || TEXT.failureOther;
}

function ConnectionTraffic({ connection }: { connection: TrafficConnectionView }) {
	const failed = connection.outcome !== null && connection.outcome !== "ok";
	return (
		<section className="space-y-4" aria-label={connection.name}>
			{failed && connection.zones.length === 0 && (
				<p role="status" className="rounded-lg border p-4 text-sm text-destructive">
					{TEXT.noZonesFailed(failureText(connection.outcome))}
				</p>
			)}
			{!failed && connection.zones.length === 0 && (
				<p className="rounded-lg border p-4 text-sm text-muted-foreground">{TEXT.noZones}</p>
			)}
			<ul className="space-y-4">
				{connection.zones.map((zone) => (
					<ZoneCard key={zone.zoneId} zone={zone} connectionName={connection.name} />
				))}
			</ul>
		</section>
	);
}

function ZoneCard({ zone, connectionName }: { zone: TrafficZoneView; connectionName: string }) {
	const first = zone.series[0];
	const last = zone.series[zone.series.length - 1];
	const peak = zone.series.reduce((best, day) => (day.mitigated > best.mitigated ? day : best), {
		day: last?.day ?? "",
		state: "read" as const,
		mitigated: 0,
	});
	const total = zone.series.reduce((sum, day) => sum + day.mitigated, 0);
	const unread = zone.series.filter((day) => day.state === "unread").length;
	const summary =
		first && last
			? TEXT.chartSummary(
					zone.series.length,
					unread,
					formatUtcDay(first.day),
					formatUtcDay(last.day),
					formatNumber(total),
					formatNumber(peak.mitigated),
					formatUtcDay(peak.day),
				)
			: "";
	const { week } = zone;
	return (
		<li className="space-y-4 rounded-lg border p-4">
			<div className="space-y-1">
				<h2 className="wrap-anywhere font-medium">{zone.name}</h2>
				<p className="text-xs text-muted-foreground">
					{TEXT.connection(connectionName)}
					{zone.plan && ` · ${TEXT.plan(zone.plan)}`}
				</p>
			</div>
			{zone.status === "ok" && first && last ? (
				<>
					<div className="space-y-2">
						<h3 className="text-sm font-medium">{TEXT.chartHeading}</h3>
						<TrafficChart series={zone.series} />
						<p className="text-sm text-muted-foreground">{summary}</p>
					</div>
					<div className="space-y-1">
						<h3 className="text-sm font-medium">{TEXT.weekHeading}</h3>
						<p className="text-sm text-muted-foreground">
							{TEXT.weekPart("this week", formatNumber(week.thisSum), week.thisRead, 7)}
							{week.lastRead === 0 ? ". " : ", "}
							{week.lastRead === 0
								? `${TEXT.weekPart("last week", "", 0, 7)}.`
								: `${TEXT.weekPart("last week", formatNumber(week.lastSum), week.lastRead, 7)}.`}
							{week.change !== null && (
								<>
									{" "}
									<span className="font-medium text-foreground">
										{TEXT.weekChange(week.change)}
									</span>
								</>
							)}
						</p>
					</div>
					<div className="grid gap-4 sm:grid-cols-3">
						<Rules rules={zone.rules} />
						<Names heading={TEXT.countriesHeading} rows={zone.countries} />
						<Names heading={TEXT.hostsHeading} rows={zone.hosts} />
					</div>
				</>
			) : (
				<p
					className={
						zone.status === "failed" ? "text-sm text-destructive" : "text-sm text-muted-foreground"
					}
				>
					{zone.status === "failed"
						? failureText(zone.failure)
						: zone.status === "not_scanned"
							? TEXT.notScanned
							: TEXT.noEvents}
				</p>
			)}
		</li>
	);
}

function Rules({ rules }: { rules: TrafficRuleView[] }) {
	return (
		<div className="min-w-0 space-y-1">
			<h3 className="text-sm font-medium">{TEXT.rulesHeading}</h3>
			{rules.length === 0 ? (
				<p className="text-sm text-muted-foreground">{TEXT.rulesNone}</p>
			) : (
				<ol className="space-y-1.5 text-sm">
					{rules.map((rule) => (
						<li key={`${rule.ruleId}/${rule.source}/${rule.action}`} className="space-y-0.5">
							<p className="wrap-anywhere">{rule.description || TEXT.noDescription}</p>
							<p className="text-xs text-muted-foreground">
								{formatNumber(rule.count)} · {TEXT.ruleOf(rule.action, rule.source)} ·{" "}
								<span title={rule.partial ? TEXT.partialHint : TEXT.sampledHint}>
									{rule.partial ? TEXT.partial : TEXT.sampled}
								</span>
							</p>
						</li>
					))}
				</ol>
			)}
		</div>
	);
}

function Names({ heading, rows }: { heading: string; rows: TrafficNameView[] }) {
	return (
		<div className="min-w-0 space-y-1">
			<h3 className="text-sm font-medium">{heading}</h3>
			{rows.length === 0 ? (
				<p className="text-sm text-muted-foreground">{TEXT.none}</p>
			) : (
				<ol className="space-y-1 text-sm">
					{rows.map((row) => (
						<li key={row.name} className="flex items-baseline justify-between gap-2">
							<span className="min-w-0 truncate" title={row.name}>
								{row.name}
							</span>
							<span className="shrink-0 text-right tabular-nums text-muted-foreground">
								{formatNumber(row.count)}
							</span>
						</li>
					))}
				</ol>
			)}
		</div>
	);
}

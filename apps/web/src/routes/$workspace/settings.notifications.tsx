import { createFileRoute, notFound } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
import { Label } from "#/components/ui/label";
import { Switch } from "#/components/ui/switch";
import { useWorkspace } from "#/components/workspace/context";
import { changeNotifications, getNotifications, type NotificationsView } from "#/lib/notifications";
import { useDocumentTitle } from "#/lib/title";

/** Everything this screen says, in one place, so it can be translated without hunting for it. */
const TEXT = {
	title: "Notifications",
	intro: (workspace: string) =>
		`Choose what Guard emails you about ${workspace}. This is only for you: everyone chooses their own.`,
	alerts: "New critical and high findings",
	alertsHint:
		"One email after a scan that finds new serious findings, at most one an hour, listing each by title and where it is.",
	digest: "Weekly summary",
	digestHint:
		"On Mondays: what is open by severity, what is new and resolved this week, and how many requests the WAF stopped or challenged.",
	where: (email: string) => `Email goes to ${email}, the address of your account.`,
	noEmail:
		"This server can't send email yet, so nothing is sent whatever you choose here. Whoever runs it can set that up.",
	defaults: "Owners and admins get both by default. Members get none until they turn them on.",
	saved: "Saved.",
	missing: "Page not found",
};

export const Route = createFileRoute("/$workspace/settings/notifications")({
	loader: async ({ params }) => {
		const view = await getNotifications({ data: params.workspace });
		if (!view) throw notFound();
		return view;
	},
	component: NotificationsPage,
});

function NotificationsPage() {
	const view = Route.useLoaderData();
	const { name } = useWorkspace();
	useDocumentTitle(TEXT.title);

	return (
		<section aria-labelledby="notifications-heading" className="space-y-6">
			<div className="space-y-1">
				<h2 id="notifications-heading" className="text-base font-semibold">
					{TEXT.title}
				</h2>
				<p className="text-sm text-muted-foreground">{TEXT.intro(name)}</p>
			</div>
			<div className="divide-y rounded-lg border">
				<Choice
					id="alert-email"
					field="alertEmail"
					label={TEXT.alerts}
					hint={TEXT.alertsHint}
					initial={view.alertEmail}
				/>
				<Choice
					id="digest-email"
					field="digestEmail"
					label={TEXT.digest}
					hint={TEXT.digestHint}
					initial={view.digestEmail}
				/>
			</div>
			<WhereItGoes view={view} />
		</section>
	);
}

function WhereItGoes({ view }: { view: NotificationsView }) {
	return (
		<div className="space-y-1 text-sm text-muted-foreground">
			<p>{TEXT.where(view.email)}</p>
			{!view.emailConfigured && <p role="note">{TEXT.noEmail}</p>}
			<p>{TEXT.defaults}</p>
		</div>
	);
}

/** One switch, which saves as soon as it moves and goes back if the server says no. */
function Choice({
	id,
	field,
	label,
	hint,
	initial,
}: {
	id: string;
	field: "alertEmail" | "digestEmail";
	label: string;
	hint: string;
	initial: boolean;
}) {
	const { slug } = useWorkspace();
	const [on, setOn] = useState(initial);
	const [pending, setPending] = useState(false);

	async function change(next: boolean) {
		setOn(next);
		setPending(true);
		const result = await changeNotifications(slug, { [field]: next });
		setPending(false);
		if (result.ok) {
			toast.success(TEXT.saved);
		} else {
			setOn(!next);
			toast.error(result.error);
		}
	}

	return (
		<div className="flex items-start justify-between gap-4 p-4">
			<div className="space-y-1">
				<Label htmlFor={id}>{label}</Label>
				<p id={`${id}-hint`} className="text-sm text-muted-foreground">
					{hint}
				</p>
			</div>
			<Switch
				id={id}
				checked={on}
				disabled={pending}
				aria-describedby={`${id}-hint`}
				onCheckedChange={(next) => void change(next)}
			/>
		</div>
	);
}

import { createFileRoute } from "@tanstack/react-router";
import { toast } from "sonner";
import { Button } from "#/components/ui/button";
import { claudeCodeCommand, getMcpAddress } from "#/lib/assistant";
import { useDocumentTitle } from "#/lib/title";

/** Everything this screen says, in one place, so it can be translated without hunting for it. */
const TEXT = {
	title: "Use Guard from your AI assistant",
	intro:
		"Connect Claude Code, Claude or any assistant that speaks MCP to Guard: paste this address into it and sign in here when it asks. There is no key to copy.",
	address: "Address",
	copy: "Copy",
	copied: "Copied",
	copyFailed: "Could not copy",
	claudeCode: "In Claude Code, one line does it:",
	can: "It acts as you, in every workspace you belong to. It can list findings, read one in full and see the traffic summary. Owners and admins can also let it dismiss a finding, with a reason, and start a scan. It never sees a token.",
	cannot:
		"It cannot connect or remove accounts or repositories, change members, or read anything you cannot. What it reads goes to the assistant you connected, so connect only ones you trust.",
	off: "This server cannot offer this yet. Whoever runs it needs to set BETTER_AUTH_URL to the server's public address. See docs/self-hosting.md in Guard's repository.",
};

export const Route = createFileRoute("/$workspace/settings/assistant")({
	loader: () => getMcpAddress(),
	component: AssistantPage,
});

async function copy(text: string, what: string) {
	try {
		await navigator.clipboard.writeText(text);
		toast.success(TEXT.copied, { description: what });
	} catch {
		toast.error(TEXT.copyFailed, { description: text });
	}
}

function AssistantPage() {
	const address = Route.useLoaderData();
	useDocumentTitle("AI assistant");

	return (
		<section aria-labelledby="assistant-heading" className="space-y-6">
			<div className="space-y-1">
				<h2 id="assistant-heading" className="text-base font-semibold">
					{TEXT.title}
				</h2>
				<p className="text-sm text-muted-foreground">{TEXT.intro}</p>
			</div>
			{address ? (
				<div className="space-y-4 rounded-lg border p-4">
					<Snippet label={TEXT.address} text={address} />
					<Snippet label={TEXT.claudeCode} text={claudeCodeCommand(address)} />
				</div>
			) : (
				<p role="note" className="rounded-lg border p-4 text-sm text-muted-foreground">
					{TEXT.off}
				</p>
			)}
			<div className="space-y-2 text-sm text-muted-foreground">
				<p>{TEXT.can}</p>
				<p>{TEXT.cannot}</p>
			</div>
		</section>
	);
}

function Snippet({ label, text }: { label: string; text: string }) {
	return (
		<div className="space-y-1.5">
			<p className="text-sm">{label}</p>
			<div className="flex items-center gap-2">
				<code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap rounded-md bg-muted px-3 py-2 font-mono text-xs">
					{text}
				</code>
				<Button type="button" variant="outline" size="sm" onClick={() => copy(text, label)}>
					{TEXT.copy}
				</Button>
			</div>
		</div>
	);
}

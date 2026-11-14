import { createFileRoute } from "@tanstack/react-router";

// Mail clients post here for one-click unsubscribe, with no session: the token is the proof.
async function unsubscribe(request: Request, token: string): Promise<Response> {
	const { handleUnsubscribe } = await import("#/server/notifications/unsubscribe");
	const { db } = await import("#/server/auth");
	return handleUnsubscribe(request, decodeToken(token), db);
}

export const Route = createFileRoute("/api/unsubscribe/$token")({
	server: {
		handlers: {
			GET: ({ request, params }) => unsubscribe(request, params.token),
			POST: ({ request, params }) => unsubscribe(request, params.token),
		},
	},
});

function decodeToken(token: string): string {
	try {
		return decodeURIComponent(token);
	} catch {
		return "";
	}
}

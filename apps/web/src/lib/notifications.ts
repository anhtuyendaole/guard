import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import type { NotificationChangeInput } from "./notification-schemas";

export * from "./notification-schemas";

/** The signed-in member's notification settings in the workspace, or null when they are not in it. */
export const getNotifications = createServerFn({ method: "GET" })
	.validator(z.string().min(1))
	.handler(async ({ data: slug }) => {
		const { listNotifications } = await import("#/server/notifications/gateway");
		return listNotifications(slug);
	});

export async function changeNotifications(
	slug: string,
	change: NotificationChangeInput,
): Promise<{ ok: true } | { ok: false; error: string }> {
	try {
		const response = await fetch(`/api/notifications/${encodeURIComponent(slug)}`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(change),
		});
		return (await response.json()) as { ok: true } | { ok: false; error: string };
	} catch {
		return { ok: false, error: "That didn't reach the server. Try again." };
	}
}

import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/notifications/$workspace")({
	server: {
		handlers: {
			GET: async ({ params }) => {
				const { readNotifications } = await import("#/server/notifications/gateway");
				return readNotifications(params.workspace);
			},
			POST: async ({ request, params }) => {
				const { changeNotifications } = await import("#/server/notifications/gateway");
				return changeNotifications(request, params.workspace);
			},
		},
	},
});

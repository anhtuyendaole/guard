import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/protection/$workspace")({
	server: {
		handlers: {
			GET: async ({ params }) => {
				const { readProtectionPage } = await import("#/server/connections/protection-gateway");
				return readProtectionPage(params.workspace);
			},
		},
	},
});

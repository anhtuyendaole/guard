import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/traffic/$workspace")({
	server: {
		handlers: {
			GET: async ({ params }) => {
				const { readTrafficPage } = await import("#/server/connections/traffic-gateway");
				return readTrafficPage(params.workspace);
			},
		},
	},
});

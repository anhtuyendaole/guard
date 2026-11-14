import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/findings/$workspace/new")({
	server: {
		handlers: {
			GET: async ({ params }) => {
				const { readNewFindingCount } = await import("#/server/connections/findings-gateway");
				return readNewFindingCount(params.workspace);
			},
		},
	},
});

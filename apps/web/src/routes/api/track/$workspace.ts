import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/track/$workspace")({
	server: {
		handlers: {
			GET: async ({ params }) => {
				const { readTrack } = await import("#/server/track/gateway");
				return readTrack(params.workspace);
			},
			POST: async ({ request, params }) => {
				const { changeTrack } = await import("#/server/track/gateway");
				return changeTrack(request, params.workspace);
			},
		},
	},
});

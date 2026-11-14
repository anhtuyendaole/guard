import { createServerFn } from "@tanstack/react-start";

/**
 * The address an AI assistant connects to, or null when this server cannot offer one: it needs
 * `BETTER_AUTH_URL`, so that the sign-in an assistant does ends where it started.
 */
export const getMcpAddress = createServerFn({ method: "GET" }).handler(async () => {
	const { mcpResource } = await import("#/server/auth");
	return mcpResource ?? null;
});

/** The one line that connects Claude Code to Guard. */
export function claudeCodeCommand(address: string): string {
	return `claude mcp add --transport http guard ${address}`;
}

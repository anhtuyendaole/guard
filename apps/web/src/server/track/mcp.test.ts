import { describe, expect, it } from "vitest";
import { z } from "zod";
import { messageIn, TrackError, TrackSession } from "./mcp";

const KEY = `gwt_${"k".repeat(43)}`;
const Answer = z.object({ value: z.number() });

/** A fetch that plays Track's MCP endpoint, for these requests in order. */
function track(
	respond: (message: { id?: number; method: string }, request: Request) => Response,
	seen: { headers: Headers; body: string; redirect: RequestRedirect | undefined }[] = [],
): typeof fetch {
	return async (input, init) => {
		const request = new Request(input, init);
		const body = await request.text();
		seen.push({ headers: request.headers, body, redirect: init?.redirect });
		const message = JSON.parse(body) as { id?: number; method: string };
		return respond(message, request);
	};
}

const sse = (id: number | undefined, result: unknown) =>
	new Response(`event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id, result })}\n\n`, {
		headers: { "content-type": "text/event-stream" },
	});

const normal = (message: { id?: number; method: string }): Response => {
	if (message.method === "initialize") return sse(message.id, { protocolVersion: "2025-06-18" });
	if (message.method === "notifications/initialized") return new Response(null, { status: 202 });
	return sse(message.id, { structuredContent: { value: 7 }, content: [] });
};

describe("messageIn", () => {
	it("finds the answer in an event stream, past other events", () => {
		const body = [
			": keep-alive",
			"",
			`data: ${JSON.stringify({ jsonrpc: "2.0", method: "notifications/progress" })}`,
			"",
			`event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: 2, result: { a: 1 } })}`,
			"",
		].join("\n");
		expect(messageIn(body, "text/event-stream", 2)?.result).toEqual({ a: 1 });
		expect(messageIn(body, "text/event-stream", 3)).toBeNull();
	});

	it("finds it in a JSON body, alone or in a batch", () => {
		const one = JSON.stringify({ jsonrpc: "2.0", id: 1, result: "x" });
		expect(messageIn(one, "application/json", 1)?.result).toBe("x");
		expect(messageIn(`[${one}]`, "application/json", 1)?.result).toBe("x");
		expect(messageIn("not json", "application/json", 1)).toBeNull();
	});
});

describe("TrackSession", () => {
	it("starts, announces itself and calls a tool, with the key as a bearer token", async () => {
		const seen: { headers: Headers; body: string; redirect: RequestRedirect | undefined }[] = [];
		const session = new TrackSession(
			{ address: "https://track.test", key: KEY },
			{ fetcher: track(normal, seen) },
		);
		const result = await session.call("get_workspace", { workspace: "acme" }, Answer);
		expect(result).toEqual({ value: 7 });
		expect(seen.map(({ body }) => (JSON.parse(body) as { method: string }).method)).toEqual([
			"initialize",
			"notifications/initialized",
			"tools/call",
		]);
		expect(seen.every(({ headers }) => headers.get("authorization") === `Bearer ${KEY}`)).toBe(
			true,
		);
		// The protocol version is sent once the server has said which it speaks.
		expect(seen[2]?.headers.get("mcp-protocol-version")).toBe("2025-06-18");
		// Never follows a redirect: the key goes only where the admin said.
		expect(seen.every(({ redirect }) => redirect === "manual")).toBe(true);
	});

	it("starts once for several calls", async () => {
		const seen: { headers: Headers; body: string; redirect: RequestRedirect | undefined }[] = [];
		const session = new TrackSession(
			{ address: "https://track.test", key: KEY },
			{ fetcher: track(normal, seen) },
		);
		await session.call("a", {}, Answer);
		await session.call("b", {}, Answer);
		expect(seen.filter(({ body }) => body.includes('"initialize"'))).toHaveLength(1);
	});

	it("reads a JSON body as well as an event stream", async () => {
		const session = new TrackSession(
			{ address: "https://track.test", key: KEY },
			{
				fetcher: track((message) => {
					if (message.method === "notifications/initialized") {
						return new Response(null, { status: 202 });
					}
					const result =
						message.method === "initialize"
							? { protocolVersion: "2025-06-18" }
							: { content: [{ type: "text", text: JSON.stringify({ value: 3 }) }] };
					return Response.json({ jsonrpc: "2.0", id: message.id, result });
				}),
			},
		);
		expect(await session.call("t", {}, Answer)).toEqual({ value: 3 });
	});

	const failure = async (fetcher: typeof fetch, options = {}) => {
		const session = new TrackSession(
			{ address: "https://track.test", key: KEY },
			{ fetcher, ...options },
		);
		const error = await session.call("t", {}, Answer).catch((caught: unknown) => caught);
		expect(error).toBeInstanceOf(TrackError);
		return error as TrackError;
	};

	it("names a revoked key", async () => {
		const error = await failure(track(() => new Response("no", { status: 401 })));
		expect(error.failure).toBe("unauthorized");
	});

	it("says a 404, a redirect and an HTML page are not Track's endpoint", async () => {
		for (const response of [
			() => new Response("nope", { status: 404 }),
			() => new Response(null, { status: 302, headers: { location: "https://elsewhere.test" } }),
		]) {
			expect((await failure(track(response))).failure).toBe("not_mcp");
		}
		const html = await failure(
			track(() => new Response("<html></html>", { headers: { "content-type": "text/html" } })),
		);
		expect(html.failure).toBe("invalid_response");
	});

	it("says a server error and a refused connection are unreachable", async () => {
		expect((await failure(track(() => new Response("x", { status: 503 })))).failure).toBe(
			"unreachable",
		);
		const refused: typeof fetch = async () => {
			throw new TypeError("connection refused");
		};
		expect((await failure(refused)).failure).toBe("unreachable");
	});

	it("gives up on a Track that does not answer", async () => {
		const hanging: typeof fetch = (_input, init) =>
			new Promise((_resolve, reject) => {
				init?.signal?.addEventListener("abort", () =>
					reject(new DOMException("t", "TimeoutError")),
				);
			});
		expect((await failure(hanging, { timeoutMs: 20 })).failure).toBe("unreachable");
	});

	it("passes on what a tool says when it refuses, and no more than its first line", async () => {
		const error = await failure(
			track((message) =>
				message.method === "tools/call"
					? sse(message.id, {
							isError: true,
							content: [{ type: "text", text: `Team XYZ not found.\n${"details ".repeat(100)}` }],
						})
					: normal(message),
			),
		);
		expect(error.failure).toBe("tool_error");
		expect(error.message).toBe("Team XYZ not found.");
	});

	it("refuses an answer of the wrong shape", async () => {
		const error = await failure(
			track((message) =>
				message.method === "tools/call"
					? sse(message.id, { structuredContent: { value: "seven" }, content: [] })
					: normal(message),
			),
		);
		expect(error.failure).toBe("invalid_response");
	});

	it("never puts the key in an error", async () => {
		const error = await failure(track(() => new Response("no", { status: 401 })));
		expect(error.message).not.toContain(KEY);
	});

	it("stops reading an answer that is far too large", async () => {
		const huge = new Response("x".repeat(2_000_000), {
			headers: { "content-type": "application/json" },
		});
		expect((await failure(track(() => huge))).failure).toBe("invalid_response");
	});
});

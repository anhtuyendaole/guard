import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { RouteError } from "./route-error";

// What a page shows when it fails to load. It used to show the error's message, which comes from
// the server: a failed database query's was its statement and every value it was given.

vi.mock("@tanstack/react-router", async (original) => ({
	...(await original<typeof import("@tanstack/react-router")>()),
	useRouter: () => ({ invalidate: () => undefined }),
}));

/** The notice for this error, as the server renders it. */
function shown(error: Error): string {
	return renderToStaticMarkup(createElement(RouteError, { error, reset: () => undefined }));
}

describe("a page that failed to load", () => {
	it("shows none of the error's message, whatever it holds", () => {
		const html = shown(
			new Error(
				'Failed query: update "connection" set "token_sealed" = ? where "connection"."id" = ?\nparams: v2.key.sealed,a-connection',
			),
		);

		expect(html).toContain("Something went wrong");
		expect(html).toContain("This page could not be loaded.");
		expect(html).toContain("Try again");
		expect(html).not.toContain("Failed query");
		expect(html).not.toContain("token_sealed");
		expect(html).not.toContain("v2.key.sealed");
		expect(html).not.toContain("a-connection");
		expect(html).not.toContain("reference");
	});

	it("shows the reference of a failed database query, to find it in the log by", () => {
		const html = shown(new Error("A database query failed (reference 1a2b3c4d)"));

		expect(html).toContain("under the reference <code>1a2b3c4d</code>.");
		expect(html).not.toContain("A database query failed");
	});

	it("finds the reference in what the error was caused by", () => {
		const cause = new Error("A database query failed (reference 0f9e8d7c)");
		const html = shown(new Error("Failed to get session", { cause }));

		expect(html).toContain("under the reference <code>0f9e8d7c</code>.");
		expect(html).not.toContain("Failed to get session");
	});
});

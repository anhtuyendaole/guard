import { createCsrfMiddleware, createMiddleware, createStart } from "@tanstack/react-start";
import { referenceIn } from "./lib/error-reference";

/**
 * Keeps a failure's reference with it on the way out of a server function. Only an error's
 * message crosses to the browser, and the reference of a failed database query may be further in:
 * Better Auth throws its own `Failed to get session` with the database's error as the cause. The
 * page would show the reference where it is rendered on the server and lose it in the browser.
 * So such an error leaves with the reference in its message, and nothing else of its cause.
 * Everything else, a redirect or a "not found" among it, is thrown as it was.
 */
const keepReference = createMiddleware({ type: "function" }).server(async ({ next }) => {
	try {
		return await next();
	} catch (error) {
		const reference = referenceIn(error);
		if (!reference || !(error instanceof Error) || referenceIn(new Error(error.message))) {
			throw error;
		}
		throw new Error(`${error.message} (reference ${reference})`);
	}
});

/**
 * The framework's own guard on server functions, listed because a start instance replaces its
 * default request middleware: without an instance every server function gets this, and with one
 * that names no `requestMiddleware` none does. It answers 403 to a server function's request
 * unless the browser says it is from this origin: `Sec-Fetch-Site: same-origin`, or without that
 * header an `Origin` that is this one, or without both a `Referer` here. A request with none of
 * the three is refused too. A session cookie comes along wherever a request is from, so this is
 * what keeps another site from asking as the person. Pages, the routes under `/api/` and `/mcp` are
 * not server functions and are left to their own checks.
 */
const sameOriginServerFunctions = createCsrfMiddleware({
	filter: (ctx) => ctx.handlerType === "serverFn",
});

export const startInstance = createStart(() => ({
	requestMiddleware: [sameOriginServerFunctions],
	functionMiddleware: [keepReference],
}));

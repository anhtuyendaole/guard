const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export type ParsedAddress = { ok: true; origin: string } | { ok: false; error: string };

/**
 * Track's address as an origin, or why it will not do. Guard sends an agent key there, so the
 * address must be one the key is safe to send to: https, with no name or password in it, and plain
 * http only to a Track on this machine, and only when Guard itself runs on this machine. The
 * address is just the origin: the MCP endpoint and the workspace are added by Guard.
 */
export function parseTrackAddress(input: string, guardOrigin: string): ParsedAddress {
	const text = input.trim();
	let url: URL;
	try {
		url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `https://${text}`);
	} catch {
		return { ok: false, error: "That isn't an address. Write it like https://track.example.com." };
	}
	const local = LOCAL_HOSTS.has(url.hostname);
	let guardIsLocal = false;
	try {
		guardIsLocal = LOCAL_HOSTS.has(new URL(guardOrigin).hostname);
	} catch {
		// An origin that does not parse is not local.
	}
	if (url.protocol === "http:") {
		if (!(local && guardIsLocal)) {
			return {
				ok: false,
				error:
					"Track's address must start with https://, so the key is not sent in the clear. http://localhost works only while Guard itself runs on localhost.",
			};
		}
	} else if (url.protocol !== "https:") {
		return { ok: false, error: "Track's address must start with https://." };
	}
	if (url.username || url.password) {
		return { ok: false, error: "Leave the name and password out of the address." };
	}
	if ((url.pathname !== "/" && url.pathname !== "") || url.search || url.hash) {
		return {
			ok: false,
			error: "Use only the address, such as https://track.example.com, without a path.",
		};
	}
	return { ok: true, origin: url.origin };
}

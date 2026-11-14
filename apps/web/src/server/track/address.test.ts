import { describe, expect, it } from "vitest";
import { parseTrackAddress } from "./address";

const cloud = "https://guard.gateweave.com";

describe("parseTrackAddress", () => {
	it("takes an https address as its origin", () => {
		expect(parseTrackAddress("https://track.gateweave.com", cloud)).toEqual({
			ok: true,
			origin: "https://track.gateweave.com",
		});
		expect(parseTrackAddress(" https://track.example.com/ ", cloud)).toEqual({
			ok: true,
			origin: "https://track.example.com",
		});
	});

	it("assumes https when the scheme is left out", () => {
		expect(parseTrackAddress("track.example.com", cloud)).toEqual({
			ok: true,
			origin: "https://track.example.com",
		});
	});

	it("refuses http, so the key is not sent in the clear", () => {
		const result = parseTrackAddress("http://track.example.com", cloud);
		expect(result.ok).toBe(false);
	});

	it("allows http to localhost only while Guard runs on localhost", () => {
		expect(parseTrackAddress("http://localhost:4710", "http://localhost:4760")).toEqual({
			ok: true,
			origin: "http://localhost:4710",
		});
		expect(parseTrackAddress("http://localhost:4710", cloud).ok).toBe(false);
		expect(parseTrackAddress("http://127.0.0.1:4710", "http://localhost:4760").ok).toBe(true);
	});

	it("refuses other schemes, a name and password, a path, a query and a fragment", () => {
		for (const bad of [
			"ftp://track.example.com",
			"javascript:alert(1)",
			"https://user:pass@track.example.com",
			"https://track.example.com/app",
			"https://track.example.com/?a=1",
			"https://track.example.com/#top",
			"not an address",
		]) {
			expect(parseTrackAddress(bad, cloud).ok, bad).toBe(false);
		}
	});
});

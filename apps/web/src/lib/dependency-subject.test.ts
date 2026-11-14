import { describe, expect, it } from "vitest";
import { parseDependencySubject } from "./dependency-subject";

describe("parseDependencySubject", () => {
	it("reads a package, its versions and its lockfile", () => {
		expect(parseDependencySubject("lodash@4.17.20, 4.17.19 in package-lock.json")).toEqual({
			package: "lodash",
			installed: ["4.17.20", "4.17.19"],
			lockfile: "package-lock.json",
		});
	});

	it("reads a scoped package, and a lockfile path with folders and spaces", () => {
		expect(parseDependencySubject("@scope/name@1.2.3 in apps/my app/pnpm-lock.yaml")).toEqual({
			package: "@scope/name",
			installed: ["1.2.3"],
			lockfile: "apps/my app/pnpm-lock.yaml",
		});
	});

	it("gives nothing for what is not a dependency's subject", () => {
		expect(parseDependencySubject("example.com")).toBeNull();
		expect(parseDependencySubject("203 Main in town")).toBeNull();
		expect(parseDependencySubject("lodash@ in package-lock.json")).toBeNull();
		expect(parseDependencySubject("lodash in package-lock.json")).toBeNull();
		expect(parseDependencySubject("lodash@1.0.0 in ")).toBeNull();
	});
});

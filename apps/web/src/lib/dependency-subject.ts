/** What a dependency finding's subject says: which package, in which versions, in which lockfile. */
export interface DependencySubject {
	package: string;
	/** The versions installed, as the lockfile has them: a package can be in a lockfile twice. */
	installed: string[];
	/** The lockfile's path in the repository. */
	lockfile: string;
}

/**
 * Reads `package@1.0.0, 1.0.1 in path/to/lockfile`, which is how the scan writes a dependency
 * finding's subject (`dependencyFindings`). Null for anything else, such as a Cloudflare finding's
 * hostname. The package can be scoped (`@scope/name`), so its version starts at the first `@` that
 * is not its first character; the lockfile's path is whole at the end and can hold spaces.
 */
export function parseDependencySubject(subject: string): DependencySubject | null {
	const split = subject.indexOf(" in ");
	if (split < 0) return null;
	const named = subject.slice(0, split);
	const lockfile = subject.slice(split + 4);
	const at = named.indexOf("@", 1);
	if (at < 1 || lockfile === "") return null;
	const installed = named
		.slice(at + 1)
		.split(", ")
		.filter((version) => version !== "");
	return installed.length > 0 ? { package: named.slice(0, at), installed, lockfile } : null;
}

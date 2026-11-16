import { drizzle } from "drizzle-orm/d1";
import { failingPlainly, withoutStatements } from "./query-failure";
import { retryingReads } from "./retry-reads";
import * as schema from "./schema";

/**
 * The database every part of the Worker asks: Better Auth, the pages' server functions and
 * endpoints, `/mcp`, the unsubscribe link and the two scheduled runs. A read that fails for a
 * moment is sent again (`retry-reads.ts`), and a query that failed for good is thrown without its
 * statement, its values or D1's words (`query-failure.ts`).
 *
 * Both hold for what is asked of the binding itself too: `db.$client` is the binding as this
 * wrapped it, and nothing else may reach `env.DB`.
 */
export function createDb(d1: D1Database) {
	// A deployment without a database serves nothing (`notSetUp` in server.ts), and has to start
	// to say so: there is no query to fail, and no binding to wrap.
	if (!d1) return drizzle(d1, { schema });
	return withoutStatements(drizzle(failingPlainly(retryingReads(d1)), { schema }));
}

export type Database = ReturnType<typeof createDb>;
export { schema };

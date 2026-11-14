import { getRequestHeaders } from "@tanstack/react-start/server";
import { db, getAuth } from "./auth";
import { findMembership, type Membership } from "./workspaces";

/**
 * Someone acting in one workspace, once it is known who they are and that they belong: what the
 * gateways do after that point is the same whether the person came from a page's session or from an
 * assistant's access token.
 */
export interface Acting {
	user: { id: string };
	membership: Membership;
}

/**
 * The signed-in user and their membership in the workspace with this slug, or null when nobody
 * is signed in or the user is not a member. Server functions that read or change a workspace
 * start here.
 */
export async function currentMember(slug: string) {
	const session = await getAuth().api.getSession({ headers: getRequestHeaders() });
	if (!session) return null;
	const membership = await findMembership(db, slug, session.user.id);
	return membership && { user: session.user, membership };
}

import { z } from "zod";

/** What a member changes about their notifications in one workspace. Each switch saves alone. */
export const NotificationChange = z
	.object({ alertEmail: z.boolean().optional(), digestEmail: z.boolean().optional() })
	.refine((change) => change.alertEmail !== undefined || change.digestEmail !== undefined, {
		message: "That isn't a change we know.",
	});

export type NotificationChangeInput = z.input<typeof NotificationChange>;

export interface NotificationsView {
	/** An email when a scan finds new critical or high findings. */
	alertEmail: boolean;
	/** The Monday summary. */
	digestEmail: boolean;
	/** Where email goes: the address of the signed-in account. */
	email: string;
	/** Whether this server can send email at all. Switches still save when it cannot. */
	emailConfigured: boolean;
}

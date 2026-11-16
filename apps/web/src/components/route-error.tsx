import { type ErrorComponentProps, useRouter } from "@tanstack/react-router";
import { Button } from "#/components/ui/button";
import { Notice } from "#/components/workspace/notice";
import { referenceIn } from "#/lib/error-reference";

const TEXT = {
	title: "Something went wrong",
	retry: "Try again",
	failed: "This page could not be loaded.",
	referenceBefore:
		"If it keeps happening, whoever runs this server can find it in the log under the reference",
};

/**
 * What a page shows when it fails to load, with a retry. No more than that it failed, never the
 * error's own message: it comes from the server, and what failed there may have put anything in
 * it, as a failed database query once put its statement and values. A reference, if the failure
 * has one, is shown so that whoever runs the server can find it in the log.
 */
export function RouteError({ error }: ErrorComponentProps) {
	const router = useRouter();
	const reference = referenceIn(error);
	return (
		<Notice
			title={TEXT.title}
			action={
				<Button variant="outline" onClick={() => void router.invalidate()}>
					{TEXT.retry}
				</Button>
			}
		>
			{TEXT.failed}
			{reference && (
				<>
					{" "}
					{TEXT.referenceBefore} <code>{reference}</code>.
				</>
			)}
		</Notice>
	);
}

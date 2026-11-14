import type { TrafficDayView } from "#/lib/connection-schemas";
import { formatUtcDay } from "#/lib/dates";
import { formatNumber } from "#/lib/numbers";

const BAR = 8;
const GAP = 2;
const HEIGHT = 40;

/**
 * Mitigated requests per day as bars, drawn inline so that there is no chart library to ship. The
 * picture is for the eye and hidden from assistive technology: the text summary beside it, which
 * the caller writes, says the same in words. Hovering a bar names its day.
 */
export function TrafficChart({ days }: { days: readonly TrafficDayView[] }) {
	const peak = Math.max(1, ...days.map((day) => day.mitigated));
	const width = days.length * (BAR + GAP) - GAP;
	return (
		<svg
			aria-hidden="true"
			focusable="false"
			viewBox={`0 0 ${Math.max(width, BAR)} ${HEIGHT}`}
			preserveAspectRatio="none"
			className="h-16 w-full text-primary"
		>
			{days.map((day, index) => {
				// A day with nothing still shows a hairline, so a quiet day is not mistaken for a missing one.
				const height = Math.max(1, Math.round((day.mitigated / peak) * HEIGHT));
				return (
					<rect
						key={day.day}
						x={index * (BAR + GAP)}
						y={HEIGHT - height}
						width={BAR}
						height={height}
						rx={1}
						className="fill-current"
					>
						<title>{`${formatUtcDay(day.day)}: ${formatNumber(day.mitigated)}`}</title>
					</rect>
				);
			})}
		</svg>
	);
}

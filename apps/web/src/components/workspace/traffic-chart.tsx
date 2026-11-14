import type { TrafficSeriesDay } from "#/lib/connection-schemas";
import { formatUtcDay } from "#/lib/dates";
import { formatNumber } from "#/lib/numbers";

const BAR = 8;
const GAP = 2;
const HEIGHT = 40;

/**
 * Mitigated requests per day over a fixed window of days, drawn inline so that there is no chart
 * library to ship. A day with nothing stopped is a thin baseline mark; a day Guard has not read is a
 * dashed empty slot, so that no data is not mistaken for a quiet day. The picture is hidden from
 * assistive technology: the text summary beside it, which the caller writes, says the same in
 * words. Hovering a slot names its day.
 */
export function TrafficChart({ series }: { series: readonly TrafficSeriesDay[] }) {
	const peak = Math.max(1, ...series.map((day) => day.mitigated));
	const width = series.length * (BAR + GAP) - GAP;
	return (
		<svg
			aria-hidden="true"
			focusable="false"
			viewBox={`0 0 ${width} ${HEIGHT}`}
			preserveAspectRatio="none"
			className="h-16 w-full text-primary"
		>
			{series.map((day, index) => {
				const x = index * (BAR + GAP);
				if (day.state === "unread") {
					return (
						<rect
							key={day.day}
							x={x + 0.5}
							y={0.5}
							width={BAR - 1}
							height={HEIGHT - 1}
							rx={1}
							fill="none"
							stroke="currentColor"
							strokeOpacity={0.35}
							strokeDasharray="2 2"
							vectorEffect="non-scaling-stroke"
						>
							<title>{`${formatUtcDay(day.day)}: not read yet`}</title>
						</rect>
					);
				}
				const height =
					day.mitigated === 0 ? 1 : Math.max(2, Math.round((day.mitigated / peak) * HEIGHT));
				return (
					<rect
						key={day.day}
						x={x}
						y={HEIGHT - height}
						width={BAR}
						height={height}
						rx={day.mitigated === 0 ? 0 : 1}
						className="fill-current"
					>
						<title>{`${formatUtcDay(day.day)}: ${formatNumber(day.mitigated)}`}</title>
					</rect>
				);
			})}
		</svg>
	);
}

import { THREAT_STYLE, normalizeThreat } from "../lib/format";

/** Compact status pill. Color is paired with a text label so it never carries meaning alone. */
export default function ThreatBadge({ level }) {
  const style = THREAT_STYLE[normalizeThreat(level)];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-sm border px-1.5 py-0.5 font-mono text-[11px] leading-none ${style.badge}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${style.dot}`} aria-hidden="true" />
      {style.label}
    </span>
  );
}
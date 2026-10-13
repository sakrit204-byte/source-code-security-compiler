const GRADE_COLOR: Record<string, string> = {
  A: "var(--accent)",
  B: "var(--sev-low)",
  C: "var(--sev-medium)",
  D: "var(--sev-high)",
  F: "var(--sev-critical)",
};

export function GradeRing({ grade, score, size = 84 }: { grade: string; score: number; size?: number }) {
  const r = size / 2 - 6;
  const c = 2 * Math.PI * r;
  const color = GRADE_COLOR[grade] ?? "var(--faint)";
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="shrink-0" aria-label={`Grade ${grade}, score ${score}`}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--line)" strokeWidth={6} />
      {score > 0 && (
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={6}
          strokeLinecap="round"
          strokeDasharray={`${(score / 100) * c} ${c}`}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{ transition: "stroke-dasharray 0.8s ease-out" }}
        />
      )}
      <text x="50%" y="47%" textAnchor="middle" dominantBaseline="middle" fontSize={size * 0.34} fontWeight={700} fill={color} fontFamily="var(--font-sans)">
        {grade}
      </text>
      <text x="50%" y="72%" textAnchor="middle" fontSize={size * 0.13} fill="var(--muted)" fontFamily="var(--font-mono)">
        {score}
      </text>
    </svg>
  );
}

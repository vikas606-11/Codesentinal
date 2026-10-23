import { scoreColor } from "../lib/lib.js";

export default function ScoreGauge({ score, rating, size = 168 }) {
  const r = 54;
  const circumference = 2 * Math.PI * r;
  const clamped = Math.max(0, Math.min(100, score));
  const dash = (clamped / 100) * circumference;
  const color = scoreColor(clamped);

  return (
    <div className="flex flex-col items-center" role="img" aria-label={`Score ${score} out of 100, ${rating}`}>
      <svg width={size} height={size} viewBox="0 0 120 120">
        <circle cx="60" cy="60" r={r} fill="none" stroke="#e2e8f0" strokeWidth="10" />
        {clamped > 0 && (
          <circle
            cx="60" cy="60" r={r} fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
            strokeDasharray={`${dash} ${circumference}`} transform="rotate(-90 60 60)"
          />
        )}
        <text x="60" y="60" textAnchor="middle" fontSize="32" fontWeight="700" fill="#0f172a">{score}</text>
        <text x="60" y="78" textAnchor="middle" fontSize="10" fill="#64748b">out of 100</text>
      </svg>
      <span className="mt-1 text-sm font-semibold" style={{ color }}>{rating}</span>
    </div>
  );
}

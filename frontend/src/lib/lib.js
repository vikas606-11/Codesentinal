export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
export const CATEGORIES = ["Security", "Quality", "Secret"];

// Full class names (Tailwind only keeps classes it can see written out)
export const SEVERITY_STYLES = {
  CRITICAL: "bg-red-100 text-red-800 ring-red-200",
  HIGH: "bg-orange-100 text-orange-800 ring-orange-200",
  MEDIUM: "bg-amber-100 text-amber-800 ring-amber-200",
  LOW: "bg-sky-100 text-sky-800 ring-sky-200",
};
export const SEVERITY_BAR = {
  CRITICAL: "bg-red-600",
  HIGH: "bg-orange-500",
  MEDIUM: "bg-amber-400",
  LOW: "bg-sky-400",
};
export const CATEGORY_STYLES = {
  Security: "bg-slate-100 text-slate-700 ring-slate-200",
  Quality: "bg-teal-100 text-teal-800 ring-teal-200",
  Secret: "bg-purple-100 text-purple-800 ring-purple-200",
};

export function scoreColor(score) {
  if (score >= 90) return "#059669";
  if (score >= 75) return "#65a30d";
  if (score >= 60) return "#d97706";
  return "#dc2626";
}

export function formatDate(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export function cweNumber(cwe) {
  const m = /(\d+)/.exec(cwe || "");
  return m ? m[1] : null;
}

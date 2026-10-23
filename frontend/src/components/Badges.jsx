import { CATEGORY_STYLES, SEVERITY_STYLES } from "../lib/lib.js";

const base = "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold ring-1 ring-inset";

export function SeverityBadge({ severity }) {
  return <span className={`${base} ${SEVERITY_STYLES[severity] || ""}`}>{severity}</span>;
}

export function CategoryBadge({ category }) {
  return <span className={`${base} ${CATEGORY_STYLES[category] || ""}`}>{category}</span>;
}

export function GateBadge({ gate }) {
  const style =
    gate === "PASS"
      ? "bg-emerald-100 text-emerald-800 ring-emerald-200"
      : "bg-red-100 text-red-800 ring-red-200";
  return <span className={`${base} ${style}`}>{gate}</span>;
}

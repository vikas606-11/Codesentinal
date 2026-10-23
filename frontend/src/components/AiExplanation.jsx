import { useEffect, useState } from "react";
import { explainFinding, getExplanation } from "../api.js";

function Section({ title, children }) {
  return (
    <div>
      <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">{title}</h4>
      <div className="mt-1 text-sm leading-relaxed text-slate-800">{children}</div>
    </div>
  );
}

export default function AiExplanation({ findingId }) {
  const [state, setState] = useState({ status: "loading", analysis: null, error: "" });

  useEffect(() => {
    let active = true;
    getExplanation(findingId)
      .then((analysis) => active && setState({ status: analysis ? "ready" : "idle", analysis, error: "" }))
      .catch((e) => active && setState({ status: "idle", analysis: null, error: e.message }));
    return () => { active = false; };
  }, [findingId]);

  const generate = async (refresh) => {
    setState((s) => ({ ...s, status: "working", error: "" }));
    try {
      const analysis = await explainFinding(findingId, refresh);
      setState({ status: "ready", analysis, error: "" });
    } catch (e) {
      setState((s) => ({ status: s.analysis ? "ready" : "idle", analysis: s.analysis, error: e.message }));
    }
  };

  const { status, analysis, error } = state;
  const builtIn = analysis && analysis.provider === "mock";

  return (
    <section aria-label="AI explanation">
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-sm font-semibold text-slate-900">Explanation and fix</h3>
        {status === "ready" && (
          <button type="button" onClick={() => generate(true)}
            className="text-xs font-medium text-slate-600 hover:underline">Regenerate</button>
        )}
      </div>

      {status === "loading" && <p className="mt-3 text-sm text-slate-500">Loading...</p>}

      {status === "idle" && (
        <div className="mt-3">
          <p className="text-sm text-slate-600">Get a plain-language explanation of this finding and how to fix it.</p>
          <button type="button" onClick={() => generate(false)}
            className="mt-3 rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700">
            Explain this finding
          </button>
        </div>
      )}

      {status === "working" && (
        <p className="mt-3 text-sm text-slate-500" role="status">Generating explanation...</p>
      )}

      {error && <p className="mt-3 rounded-md bg-red-50 p-3 text-sm text-red-800" role="alert">{error}</p>}

      {analysis && status !== "working" && (
        <div className="mt-4 space-y-4">
          <p className="text-xs text-slate-500" data-testid="ai-source">
            {builtIn ? "Built-in explanation (no AI model was used)" : `AI explanation by ${analysis.provider} (${analysis.model})`}
          </p>
          {analysis.note && (
            <p className="rounded-md bg-amber-50 p-3 text-xs text-amber-900" data-testid="ai-note">{analysis.note}</p>
          )}
          <Section title="What is the problem">{analysis.problem}</Section>
          <Section title="Why it is dangerous">{analysis.why_dangerous}</Section>
          <Section title="Where">{analysis.location}</Section>
          <Section title="Potential impact">{analysis.impact}</Section>
          <Section title="How to fix">
            <ol className="list-decimal space-y-1 pl-5">
              {analysis.how_to_fix.map((step, i) => <li key={i}>{step}</li>)}
            </ol>
          </Section>
          {analysis.secure_example && (
            <Section title="Secure example">
              <pre className="overflow-x-auto rounded-md bg-slate-900 p-4 text-xs leading-relaxed text-slate-100"><code>{analysis.secure_example}</code></pre>
            </Section>
          )}
        </div>
      )}
    </section>
  );
}

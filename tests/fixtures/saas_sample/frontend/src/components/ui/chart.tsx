// Regression fixture mirroring a REAL 9_Agent_SaaS finding: the shadcn chart
// component injects per-chart CSS through a raw-HTML sink.
// Expected: frontend-xss/dangerously-set-inner-html (HIGH).
export function ChartStyle({ id, colorConfig }: { id: string; colorConfig: string }) {
  return (
    <style
      dangerouslySetInnerHTML={{
        __html: `[data-chart=${id}] { ${colorConfig} }`,
      }}
    />
  );
}

export function renderReport(apiResponse: { script: string; summary: string }) {
  // Mistake: executes a script string returned by the API/LLM.
  eval(apiResponse.script);

  // Safe: literal-only eval, and plain-text assignment for the summary.
  eval("console.log('report rendered')");
  const el = document.getElementById("summary");
  if (el) {
    el.textContent = apiResponse.summary;
  }
}

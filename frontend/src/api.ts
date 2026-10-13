import type { RuleMeta, Sample, ScanResult } from "./types";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body?.detail) detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* non-JSON error body */
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export const api = {
  scan: (code: string, filename: string, disabledRules: string[] = []) =>
    request<ScanResult>("/api/scan", {
      method: "POST",
      body: JSON.stringify({ code, filename, disabled_rules: disabledRules }),
    }),
  samples: () => request<{ samples: Sample[] }>("/api/samples").then((r) => r.samples),
  rules: () => request<{ rules: RuleMeta[] }>("/api/rules").then((r) => r.rules),
  async export(code: string, filename: string, format: "html" | "text" | "json") {
    const res = await fetch("/api/export", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, filename, format }),
    });
    if (!res.ok) throw new Error(`Export failed (${res.status})`);
    const blob = await res.blob();
    const stem = filename.replace(/\.[^.]+$/, "") || "report";
    const ext = format === "text" ? "txt" : format;
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${stem}-report.${ext}`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  },
};

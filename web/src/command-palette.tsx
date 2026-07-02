import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import { ApiClient, toHex, type SearchResult } from "./api";

const KIND_LABEL: Record<string, string> = {
  address: "addr",
  function: "func",
  string: "str",
  name: "name",
};

// Ctrl-K search over functions, strings, names and a raw address, served by the
// plugin's /api/search. Keyboard-driven: arrows to move, Enter to jump, Esc closes.
export function CommandPalette({
  client,
  onNavigate,
  onClose,
}: {
  client: ApiClient;
  onNavigate: (ea: string) => void;
  onClose: () => void;
}) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResult[]>([]);
  const [sel, setSel] = useState(0);
  const [busy, setBusy] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  useEffect(() => {
    const q = query.trim();
    if (!q) {
      setResults([]);
      return;
    }
    let cancelled = false;
    setBusy(true);
    const timer = setTimeout(async () => {
      try {
        const found = await client.search(q);
        if (!cancelled) {
          setResults(found);
          setSel(0);
        }
      } catch {
        if (!cancelled) setResults([]);
      } finally {
        if (!cancelled) setBusy(false);
      }
    }, 220);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [query, client]);

  function choose(result: SearchResult) {
    onNavigate(result.ea);
    onClose();
  }

  function onKeyDown(e: KeyboardEvent) {
    if (e.key === "Escape") onClose();
    else if (e.key === "ArrowDown") {
      e.preventDefault();
      setSel((s) => Math.min(s + 1, results.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSel((s) => Math.max(s - 1, 0));
    } else if (e.key === "Enter" && results[sel]) {
      e.preventDefault();
      choose(results[sel]);
    }
  }

  return (
    <div className="palette-overlay" onClick={onClose}>
      <div className="palette" onClick={(e) => e.stopPropagation()}>
        <input
          ref={inputRef}
          className="palette-input mono"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder="Search functions, strings, names, or an address…"
        />
        <div className="palette-results">
          {busy && <div className="palette-empty dim">Searching…</div>}
          {!busy && query.trim() && results.length === 0 && <div className="palette-empty dim">No results</div>}
          {results.map((r, i) => (
            <div
              key={`${r.kind}-${r.ea}-${i}`}
              className={`palette-row ${i === sel ? "active" : ""}`}
              onMouseMove={() => setSel(i)}
              onClick={() => choose(r)}
            >
              <span className={`palette-kind kind-${r.kind}`}>{KIND_LABEL[r.kind]}</span>
              <span className="palette-label">{r.label}</span>
              <span className="palette-ea dim mono">{toHex(r.ea)}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

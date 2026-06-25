import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  ApiClient,
  toHex,
  eaAdd,
  type Ea,
  type Info,
  type FunctionEntry,
  type Disassembly,
  type Graph,
  type Pseudocode,
  type Xref,
  type StringItem,
  type ImportItem,
  type ExportItem,
  type HexResult,
  type SegmentItem,
  type NameItem,
  type LocalType,
} from "./api";
import { renderTokens } from "./render-tokens";
import { GraphView } from "./graph-view";
import { VirtualList } from "./virtual-list";
import "./app.css";

type Tab = "disasm" | "graph" | "pseudo" | "hex" | "strings" | "names" | "imports" | "exports" | "segments" | "types";

const TABS: Tab[] = ["disasm", "graph", "pseudo", "hex", "strings", "names", "imports", "exports", "segments", "types"];
const TAB_LABEL: Record<Tab, string> = {
  disasm: "Disassembly",
  graph: "Graph",
  pseudo: "Pseudocode",
  hex: "Hex",
  strings: "Strings",
  names: "Names",
  imports: "Imports",
  exports: "Exports",
  segments: "Segments",
  types: "Local Types",
};

// Turn the host/port fields into a base URL. A full "https://…" host (e.g. a
// tunnel) is used as-is; a bare host/IP is wrapped with http:// and the port.
function buildBaseUrl(host: string, port: string): string {
  const h = host.trim().replace(/\/$/, "");
  const p = port.trim();
  if (h.includes("://")) return p && !/:\d+$/.test(h) ? `${h}:${p}` : h;
  return `http://${h}${p ? ":" + p : ""}`;
}

// Where to point the client by default. When the page is served by the plugin
// (directly or through a tunnel/public domain) the API is on this same origin,
// so prefill it — over a tunnel you then only need to enter the token. On the
// Vite dev server (5173) there's no API, so fall back to the local plugin.
function defaultTarget(): { host: string; port: string } {
  const loc = window.location;
  if (/^517\d$/.test(loc.port)) return { host: "localhost", port: "8765" };
  return { host: loc.origin, port: "" };
}

export default function App() {
  const [host, setHost] = useState(() => defaultTarget().host);
  const [port, setPort] = useState(() => defaultTarget().port);
  const [token, setToken] = useState("");
  const [client, setClient] = useState<ApiClient | null>(null);
  const [info, setInfo] = useState<Info | null>(null);
  const [functions, setFunctions] = useState<FunctionEntry[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const [filter, setFilter] = useState("");
  const [selected, setSelected] = useState<FunctionEntry | null>(null);
  const [tab, setTab] = useState<Tab>("disasm");
  const [disasm, setDisasm] = useState<Disassembly | null>(null);
  const [graph, setGraph] = useState<Graph | null>(null);
  const [pseudo, setPseudo] = useState<Pseudocode | null>(null);
  const [xrefs, setXrefs] = useState<Xref[]>([]);

  const [strings, setStrings] = useState<StringItem[] | null>(null);
  const [imports, setImports] = useState<ImportItem[] | null>(null);
  const [exports, setExports] = useState<ExportItem[] | null>(null);
  const [segments, setSegments] = useState<SegmentItem[] | null>(null);
  const [names, setNames] = useState<NameItem[] | null>(null);
  const [localTypes, setLocalTypes] = useState<LocalType[] | null>(null);
  const [hexAddr, setHexAddr] = useState("");
  const [hexData, setHexData] = useState<HexResult | null>(null);
  const [stringFilter, setStringFilter] = useState("");
  const [strXrefs, setStrXrefs] = useState<{ ea: Ea; items: Xref[] } | null>(null);
  const [highlightEa, setHighlightEa] = useState<Ea | null>(null);
  const [follow, setFollow] = useState(false);
  const [drive, setDrive] = useState(false);
  const [navOpen, setNavOpen] = useState(false);
  const [theme, setTheme] = useState(() => localStorage.getItem("idarem-theme") || "dark");

  useEffect(() => {
    document.documentElement.dataset.theme = theme; // theme the whole document
    localStorage.setItem("idarem-theme", theme);
  }, [theme]);

  async function connect() {
    setError("");
    setBusy(true);
    try {
      const next = new ApiClient(buildBaseUrl(host, port), token);
      const [fetchedInfo, fetchedFunctions] = await Promise.all([next.info(), next.functions()]);
      setClient(next);
      setInfo(fetchedInfo);
      setFunctions(fetchedFunctions);
      setSelected(null);
      setDisasm(null);
      setGraph(null);
      setPseudo(null);
      setXrefs([]);
      setStrings(null);
      setImports(null);
      setExports(null);
      setSegments(null);
      setNames(null);
      setLocalTypes(null);
      setHexData(null);
      setStrXrefs(null);
      setHighlightEa(null);
      setHexAddr(toHex(fetchedInfo.image_base));
    } catch (e) {
      setError(`Connection failed: ${(e as Error).message}`);
      setClient(null);
      setInfo(null);
    } finally {
      setBusy(false);
    }
  }

  function disconnect() {
    setClient(null);
    setInfo(null);
    setError("");
  }

  async function selectFunction(fn: FunctionEntry) {
    if (!client) return;
    setNavOpen(false); // close the mobile function drawer once one is picked
    setSelected(fn);
    setDisasm(null);
    setGraph(null);
    setPseudo(null);
    setXrefs([]);
    try {
      const [d, x] = await Promise.all([client.disasm(fn.ea), client.xrefs(fn.ea)]);
      setDisasm(d);
      setXrefs(x);
      // Graph and pseudocode are loaded only for the tab actually in view —
      // decompilation in particular is too expensive to run on every click.
      if (tab === "graph") setGraph(await client.graph(fn.ea));
      if (tab === "pseudo" && info?.has_hexrays) setPseudo(await client.pseudocode(fn.ea));
    } catch (e) {
      setError(`Load failed: ${(e as Error).message}`);
    }
  }

  function findFunction(addr: Ea): FunctionEntry | undefined {
    let a: bigint;
    try {
      a = BigInt(addr);
    } catch {
      return undefined;
    }
    return (
      functions.find((f) => BigInt(f.ea) === a) ??
      functions.find((f) => {
        const start = BigInt(f.ea);
        return a >= start && a < start + BigInt(f.size);
      })
    );
  }

  function navigateToAddress(addr: Ea, switchTab = true) {
    const target = findFunction(addr);
    if (!target) {
      // Not inside a function (e.g. an import slot or data) — show it in Hex.
      if (switchTab) goToHexAt(addr);
      return;
    }
    // Always move the view to the function (so re-clicking a name while on
    // another tab brings its code back); only refetch when it actually changes.
    if (switchTab) {
      setTab((t) => (t === "pseudo" || t === "graph" ? t : "disasm"));
      setHighlightEa(addr); // scroll to and flash the exact line
      driveTo(addr); // mirror to IDA when "Drive IDA" is on
    }
    if (target.ea !== selected?.ea) selectFunction(target);
  }

  // Live refs so the EventSource handler always calls the latest closures.
  const navRef = useRef(navigateToAddress);
  navRef.current = navigateToAddress;
  const showTabRef = useRef<(t: Tab) => void>(() => {});

  // The disassembly line currently flagged for the flash highlight.
  const flashRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (highlightEa && flashRef.current) flashRef.current.scrollIntoView({ block: "center", behavior: "smooth" });
  }, [highlightEa, disasm]);

  // "Follow IDA": mirror IDA's current address and active view (which window
  // you're in — disassembly, pseudocode, strings, …) over SSE.
  useEffect(() => {
    if (!follow || !client) return;
    const source = new EventSource(client.eventsUrl());
    source.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data) as { type: string; ea?: string; view?: string };
        // Address selects the function; the tab is driven by "view" events, so
        // don't let address-follow override the active tab.
        if (msg.type === "screen_ea" && msg.ea) navRef.current(msg.ea, false);
        else if (msg.type === "view" && msg.view && (TABS as string[]).includes(msg.view)) showTabRef.current(msg.view as Tab);
      } catch {
        // ignore malformed events
      }
    };
    return () => source.close();
  }, [follow, client]);

  async function loadHexAt(addrText: string) {
    if (!client) return;
    const ea = toHex(addrText.trim());
    try {
      BigInt(ea);
    } catch {
      return; // not a valid address
    }
    try {
      setHexData(await client.hex(ea, 2048));
    } catch (e) {
      setError(`Load failed: ${(e as Error).message}`);
    }
  }

  async function showStringXrefs(ea: Ea) {
    if (!client) return;
    try {
      setStrXrefs({ ea, items: await client.xrefs(ea) });
    } catch (e) {
      setError(`Load failed: ${(e as Error).message}`);
    }
  }

  function goToHexAt(ea: Ea) {
    setHexAddr(ea);
    setTab("hex");
    loadHexAt(ea);
    driveTo(ea);
  }

  // Web -> IDA: when "Drive IDA" is on, send the address for IDA to jump to.
  function driveTo(ea: Ea) {
    if (drive && client) client.goto(ea).catch(() => {});
  }

  async function renameFunction() {
    if (!client || !selected) return;
    const name = window.prompt("Rename function", selected.name);
    if (name === null || name === selected.name) return;
    try {
      await client.rename(selected.ea, name);
      const fns = await client.functions();
      setFunctions(fns);
      setSelected(fns.find((f) => f.ea === selected.ea) ?? selected);
      setDisasm(await client.disasm(selected.ea));
      if (tab === "pseudo" && info?.has_hexrays) setPseudo(await client.pseudocode(selected.ea));
    } catch (e) {
      setError(`Rename failed: ${(e as Error).message}`);
    }
  }

  async function setCommentAt(ea: Ea) {
    if (!client || !selected) return;
    const text = window.prompt(`Comment at ${toHex(ea)}`, "");
    if (text === null) return;
    try {
      await client.comment(ea, text);
      setDisasm(await client.disasm(selected.ea));
    } catch (e) {
      setError(`Comment failed: ${(e as Error).message}`);
    }
  }

  async function showTab(next: Tab) {
    setTab(next);
    if (!client) return;
    try {
      if (next === "graph" && graph === null && selected) setGraph(await client.graph(selected.ea));
      if (next === "pseudo" && pseudo === null && selected && info?.has_hexrays) setPseudo(await client.pseudocode(selected.ea));
      if (next === "strings" && strings === null) setStrings(await client.strings());
      if (next === "imports" && imports === null) setImports(await client.imports());
      if (next === "exports" && exports === null) setExports(await client.exports());
      if (next === "segments" && segments === null) setSegments(await client.segments());
      if (next === "names" && names === null) setNames(await client.names());
      if (next === "types" && localTypes === null) {
        const result = await client.localTypes();
        setLocalTypes(result.items);
        if (result.error) setError(`Local types: ${result.error}`);
      }
      if (next === "hex" && hexData === null) await loadHexAt(hexAddr || info?.image_base || "0");
    } catch (e) {
      setError(`Load failed: ${(e as Error).message}`);
    }
  }
  showTabRef.current = showTab;

  const visibleFunctions = useMemo(() => {
    const needle = filter.toLowerCase();
    return needle ? functions.filter((f) => f.name.toLowerCase().includes(needle)) : functions;
  }, [functions, filter]);

  const visibleStrings = useMemo(() => {
    const list = strings ?? [];
    const needle = stringFilter.toLowerCase();
    return needle ? list.filter((s) => s.text.toLowerCase().includes(needle) || toHex(s.ea).toLowerCase().includes(needle)) : list;
  }, [strings, stringFilter]);

  // Connection screen — shown until a session is established.
  if (!info) {
    return (
      <div className="connect">
        <form
          className="connect-card"
          onSubmit={(e) => {
            e.preventDefault();
            if (!busy) connect();
          }}
        >
          <h1 className="connect-title">idarem</h1>
          <p className="connect-sub dim">Review an IDA database from your browser</p>
          <div className="connect-row">
            <input className="grow" value={host} onChange={(e) => setHost(e.target.value)} placeholder="IP / host (e.g. 192.168.1.10)" />
            <input className="port" value={port} onChange={(e) => setPort(e.target.value)} placeholder="port" />
          </div>
          <input value={token} onChange={(e) => setToken(e.target.value)} placeholder="token (optional)" />
          <button type="submit" disabled={busy}>
            {busy ? "Connecting…" : "Connect"}
          </button>
          {error && <div className="connect-error">{error}</div>}
        </form>
      </div>
    );
  }

  return (
    <div className="app">
      <header className="bar">
        <button className="navtoggle" onClick={() => setNavOpen((o) => !o)} title="Toggle function list" aria-label="Toggle function list">
          ☰
        </button>
        <strong>idarem</strong>
        <span className="dim info">
          {info.file} · {info.processor} · {info.bits}-bit · {info.has_hexrays ? "Hex-Rays" : "no decompiler"} · {functions.length} funcs
        </span>
        <select className="theme-select" value={theme} onChange={(e) => setTheme(e.target.value)} title="Theme">
          <option value="dark">Dark</option>
          <option value="darcula">Darcula</option>
          <option value="light">Light</option>
        </select>
        <button className={follow ? "follow on" : "follow"} onClick={() => setFollow((f) => !f)} title="Follow IDA's current address">
          {follow ? "● Following" : "Follow"}
        </button>
        <button className={drive ? "follow on" : "follow"} onClick={() => setDrive((d) => !d)} title="Send your clicks to IDA and enable rename/comment">
          {drive ? "● Driving" : "Drive"}
        </button>
        <button onClick={disconnect}>Disconnect</button>
      </header>

      {error && <div className="error">{error}</div>}

      <div className="body">
        {navOpen && <div className="backdrop" onClick={() => setNavOpen(false)} />}
        <aside className={`sidebar ${navOpen ? "open" : ""}`}>
          <input className="filter" value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter functions..." />
          <VirtualList
            className="list"
            items={visibleFunctions}
            rowHeight={22}
            renderRow={(fn) => (
              <div
                key={fn.ea}
                className={`row ${selected?.ea === fn.ea ? "active" : ""}`}
                onClick={() => {
                  selectFunction(fn);
                  driveTo(fn.ea);
                }}
                title={fn.ea}
              >
                <span className="mono dim">{toHex(fn.ea)}</span> {fn.name}
              </div>
            )}
          />
        </aside>

        <main className="content">
          <div className="tabs">
            {TABS.map((t) => (
              <button key={t} className={tab === t ? "on" : ""} onClick={() => showTab(t)} disabled={t === "pseudo" && !info?.has_hexrays}>
                {TAB_LABEL[t]}
              </button>
            ))}
            {(tab === "disasm" || tab === "graph" || tab === "pseudo") && selected && (
              <span className="dim mono">
                {selected.name} @ {toHex(selected.ea)}
                {drive && (
                  <button className="edit" onClick={renameFunction} title="Rename function">
                    ✎
                  </button>
                )}
              </span>
            )}
          </div>

          {(tab === "disasm" || tab === "graph" || tab === "pseudo") && !selected && (
            <div className="placeholder">Pick a function from the list.</div>
          )}

          {tab === "disasm" && selected && (
            <div className="view mono">
              {disasm ? (
                disasm.lines.map((line) => {
                  const flashing = line.ea === highlightEa;
                  return (
                    <div
                      className={`codeline ${flashing ? "flash" : ""}`}
                      key={line.ea}
                      ref={flashing ? flashRef : undefined}
                      onAnimationEnd={flashing ? () => setHighlightEa(null) : undefined}
                    >
                      <span
                        className={`dim ${drive ? "addr-edit" : ""}`}
                        onClick={drive ? () => setCommentAt(line.ea) : undefined}
                        title={drive ? "Add / edit comment" : undefined}
                      >
                        {toHex(line.ea)}
                      </span>{" "}
                      {renderTokens(line.tokens, navigateToAddress)}
                    </div>
                  );
                })
              ) : (
                <div className="dim">Loading...</div>
              )}
            </div>
          )}

          {tab === "graph" &&
            selected &&
            (graph ? (
              <GraphView graph={graph} onNavigate={navigateToAddress} />
            ) : (
              <div className="view dim">Loading...</div>
            ))}

          {tab === "pseudo" && selected && (
            <div className="view mono">
              {pseudo ? (
                pseudo.lines.map((line, i) => (
                  <div className="codeline" key={i}>
                    {renderTokens(line.tokens, navigateToAddress)}
                  </div>
                ))
              ) : (
                <div className="dim">Loading...</div>
              )}
            </div>
          )}

          {tab === "hex" && (
            <>
              <div className="subbar">
                <input
                  className="mono"
                  value={hexAddr}
                  onChange={(e) => setHexAddr(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && loadHexAt(hexAddr)}
                  placeholder="address (hex)"
                />
                <button onClick={() => loadHexAt(hexAddr)}>Go</button>
              </div>
              {hexData ? <HexView data={hexData} /> : <div className="view dim">Loading...</div>}
            </>
          )}

          {tab === "strings" && (
            <>
              <div className="subbar">
                <input
                  className="grow"
                  value={stringFilter}
                  onChange={(e) => setStringFilter(e.target.value)}
                  placeholder="Search strings..."
                />
                <span className="dim">{visibleStrings.length}</span>
              </div>
              <DataTable
                columns={["Address", "Length", "String"]}
                template="15ch 7ch 1fr"
                rows={visibleStrings.map((s) => [toHex(s.ea), String(s.length), s.text])}
                addresses={visibleStrings.map((s) => s.ea)}
                onNavigate={showStringXrefs}
                onActivate={goToHexAt}
                selectedRow={strXrefs ? visibleStrings.findIndex((s) => s.ea === strXrefs.ea) : undefined}
                loading={strings === null}
              />
              {strXrefs && (
                <div className="xrefs">
                  <div className="dim">
                    Xrefs to <span className="mono">{toHex(strXrefs.ea)}</span> ({strXrefs.items.length}) ·{" "}
                    <span className="ref" onClick={() => goToHexAt(strXrefs.ea)}>
                      open in Hex
                    </span>
                  </div>
                  {strXrefs.items.length === 0 && <div className="dim">no cross-references</div>}
                  {strXrefs.items.map((x, i) => (
                    <div className="xref mono ref" key={i} onClick={() => navigateToAddress(x.frm)}>
                      <span className="dim">{toHex(x.frm)}</span> {x.name || "—"}
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
          {tab === "names" && (
            <DataTable
              columns={["Address", "Name"]}
              template="15ch 1fr"
              rows={(names ?? []).map((n) => [toHex(n.ea), n.name])}
              addresses={(names ?? []).map((n) => n.ea)}
              onNavigate={navigateToAddress}
              loading={names === null}
            />
          )}
          {tab === "imports" && (
            <DataTable
              columns={["Address", "Module", "Name", "Ordinal"]}
              template="15ch 12ch 1fr 7ch"
              rows={(imports ?? []).map((m) => [toHex(m.ea), m.module, m.name || "(ordinal)", m.ordinal ? String(m.ordinal) : ""])}
              addresses={(imports ?? []).map((m) => m.ea)}
              onNavigate={navigateToAddress}
              loading={imports === null}
            />
          )}
          {tab === "exports" && (
            <DataTable
              columns={["Address", "Ordinal", "Name"]}
              template="15ch 7ch 1fr"
              rows={(exports ?? []).map((x) => [toHex(x.ea), String(x.ordinal), x.name])}
              addresses={(exports ?? []).map((x) => x.ea)}
              onNavigate={navigateToAddress}
              loading={exports === null}
            />
          )}
          {tab === "segments" && (
            <DataTable
              columns={["Name", "Start", "End", "Class", "Perm"]}
              template="1fr 15ch 15ch 9ch 6ch"
              rows={(segments ?? []).map((s) => [s.name, toHex(s.start), toHex(s.end), s.class, String(s.perm)])}
              addresses={(segments ?? []).map((s) => s.start)}
              onNavigate={navigateToAddress}
              loading={segments === null}
            />
          )}
          {tab === "types" && (
            <DataTable
              columns={["Ordinal", "Name", "Declaration"]}
              template="7ch 1fr 2fr"
              rows={(localTypes ?? []).map((t) => [String(t.ordinal), t.name, t.decl])}
              loading={localTypes === null}
            />
          )}

          {(tab === "disasm" || tab === "pseudo") && selected && xrefs.length > 0 && (
            <div className="xrefs">
              <div className="dim">Cross-references ({xrefs.length})</div>
              {xrefs.map((x, i) => (
                <div className="xref mono ref" key={i} onClick={() => navigateToAddress(x.frm)}>
                  <span className="dim">{toHex(x.frm)}</span> {x.name || "—"}
                </div>
              ))}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

function HexView({ data }: { data: HexResult }) {
  const bytes: number[] = [];
  for (let i = 0; i + 1 < data.hex.length; i += 2) bytes.push(parseInt(data.hex.slice(i, i + 2), 16));

  const rows: ReactNode[] = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const slice = bytes.slice(offset, offset + 16);
    const hex = slice.map((b) => b.toString(16).padStart(2, "0").toUpperCase()).join(" ");
    const ascii = slice.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    rows.push(
      <div className="codeline" key={offset}>
        <span className="dim">{eaAdd(data.ea, offset)}</span>
        {"  " + hex.padEnd(47) + "  " + ascii}
      </div>,
    );
  }
  return <div className="view mono">{rows}</div>;
}

function DataTable(props: {
  columns: string[];
  template: string;
  rows: string[][];
  addresses?: Ea[];
  onNavigate?: (addr: Ea) => void;
  onActivate?: (addr: Ea) => void;
  selectedRow?: number;
  loading: boolean;
}) {
  if (props.loading) return <div className="view dim">Loading...</div>;
  const interactive = props.addresses && (props.onNavigate || props.onActivate);
  return (
    <div className="dtable mono">
      <div className="dthead" style={{ gridTemplateColumns: props.template }}>
        {props.columns.map((c) => (
          <div key={c}>{c}</div>
        ))}
      </div>
      <VirtualList
        className="dtbody"
        items={props.rows}
        rowHeight={24}
        renderRow={(row, i) => {
          const addr = props.addresses?.[i];
          return (
            <div
              key={i}
              className={`dtrow ${interactive ? "clickable" : ""} ${props.selectedRow === i ? "active" : ""}`}
              style={{ gridTemplateColumns: props.template }}
              onClick={() => addr !== undefined && props.onNavigate?.(addr)}
              onDoubleClick={() => addr !== undefined && props.onActivate?.(addr)}
            >
              {row.map((cell, j) => (
                <div key={j} title={cell}>
                  {cell}
                </div>
              ))}
            </div>
          );
        }}
      />
    </div>
  );
}

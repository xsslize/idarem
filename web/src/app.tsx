import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  ApiClient,
  HttpError,
  findFunctionByAddress,
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
import { CommandPalette } from "./command-palette";
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
  if (h.includes("://")) {
    const url = new URL(h);
    if (p && !url.port) url.port = p;
    return url.toString().replace(/\/$/, "");
  }
  const normalized = h.includes(":") && !h.startsWith("[") ? `[${h}]` : h;
  return `http://${normalized}${p ? ":" + p : ""}`;
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
  const [xrefsTruncated, setXrefsTruncated] = useState(false);

  const [strings, setStrings] = useState<StringItem[] | null>(null);
  const [imports, setImports] = useState<ImportItem[] | null>(null);
  const [exports, setExports] = useState<ExportItem[] | null>(null);
  const [segments, setSegments] = useState<SegmentItem[] | null>(null);
  const [names, setNames] = useState<NameItem[] | null>(null);
  const [localTypes, setLocalTypes] = useState<LocalType[] | null>(null);
  const [hexAddr, setHexAddr] = useState("");
  const [hexData, setHexData] = useState<HexResult | null>(null);
  const [stringFilter, setStringFilter] = useState("");
  const [strXrefs, setStrXrefs] = useState<{ ea: Ea; items: Xref[]; truncated: boolean } | null>(null);
  const [highlightEa, setHighlightEa] = useState<Ea | null>(null);
  const [follow, setFollow] = useState(false);
  const [followStatus, setFollowStatus] = useState<"idle" | "connected" | "reconnecting">("idle");
  const [drive, setDrive] = useState(false);
  const [navOpen, setNavOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [tokenVisible, setTokenVisible] = useState(false);
  const [theme, setTheme] = useState(() => localStorage.getItem("idarem-theme") || "dark");
  const selectionRequest = useRef<AbortController | null>(null);
  const selectionGeneration = useRef(0);
  const tabGeneration = useRef(0);
  const hexGeneration = useRef(0);
  const stringXrefGeneration = useRef(0);
  const selectedRef = useRef<FunctionEntry | null>(null);
  const clientRef = useRef<ApiClient | null>(null);
  selectedRef.current = selected;
  clientRef.current = client;

  const functionsByAddress = useMemo(
    () => [...functions].sort((left, right) => (BigInt(left.ea) < BigInt(right.ea) ? -1 : BigInt(left.ea) > BigInt(right.ea) ? 1 : 0)),
    [functions],
  );

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
      clientRef.current = next;
      tabGeneration.current++;
      setClient(next);
      setInfo(fetchedInfo);
      setFunctions(fetchedFunctions);
      setSelected(null);
      setDisasm(null);
      setGraph(null);
      setPseudo(null);
      setXrefs([]);
      setXrefsTruncated(false);
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
      clientRef.current = null;
      setClient(null);
      setInfo(null);
    } finally {
      setBusy(false);
    }
  }

  function disconnect() {
    selectionRequest.current?.abort();
    selectionGeneration.current++;
    tabGeneration.current++;
    hexGeneration.current++;
    stringXrefGeneration.current++;
    clientRef.current = null;
    setClient(null);
    setInfo(null);
    setFunctions([]);
    setSelected(null);
    setDisasm(null);
    setGraph(null);
    setPseudo(null);
    setXrefs([]);
    setXrefsTruncated(false);
    setStrings(null);
    setImports(null);
    setExports(null);
    setSegments(null);
    setNames(null);
    setLocalTypes(null);
    setHexData(null);
    setStrXrefs(null);
    setHighlightEa(null);
    setFollow(false);
    setFollowStatus("idle");
    setDrive(false);
    setNavOpen(false);
    setPaletteOpen(false);
    setToken("");
    setFilter("");
    setStringFilter("");
    setError("");
  }

  async function selectFunction(fn: FunctionEntry) {
    if (!client) return;
    selectionRequest.current?.abort();
    const controller = new AbortController();
    selectionRequest.current = controller;
    const generation = ++selectionGeneration.current;
    setNavOpen(false); // close the mobile function drawer once one is picked
    setSelected(fn);
    setDisasm(null);
    setGraph(null);
    setPseudo(null);
    setXrefs([]);
    setXrefsTruncated(false);
    try {
      const [d, x] = await Promise.all([client.disasm(fn.ea, controller.signal), client.xrefs(fn.ea, controller.signal)]);
      if (controller.signal.aborted || generation !== selectionGeneration.current) return;
      setDisasm(d);
      setXrefs(x.items);
      setXrefsTruncated(x.truncated);
      // Graph and pseudocode are loaded only for the tab actually in view —
      // decompilation in particular is too expensive to run on every click.
      if (tab === "graph") {
        const nextGraph = await client.graph(fn.ea, controller.signal);
        if (!controller.signal.aborted && generation === selectionGeneration.current) setGraph(nextGraph);
      }
      if (tab === "pseudo" && info?.has_hexrays) {
        const nextPseudo = await client.pseudocode(fn.ea, controller.signal);
        if (!controller.signal.aborted && generation === selectionGeneration.current) setPseudo(nextPseudo);
      }
    } catch (e) {
      if (!controller.signal.aborted) setError(`Load failed: ${(e as Error).message}`);
    }
  }

  function findFunction(addr: Ea): FunctionEntry | undefined {
    return findFunctionByAddress(functionsByAddress, addr);
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

  // Live refs so the SSE handler always calls the latest closures.
  const navRef = useRef(navigateToAddress);
  navRef.current = navigateToAddress;
  const showTabRef = useRef<(t: Tab) => void>(() => {});

  // The disassembly line currently flagged for the flash highlight.
  const flashRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (highlightEa && flashRef.current) flashRef.current.scrollIntoView({ block: "center", behavior: "smooth" });
  }, [highlightEa, disasm]);

  // "Follow IDA": mirror IDA's current address and active view over SSE.
  useEffect(() => {
    if (!follow || !client) {
      setFollowStatus("idle");
      return;
    }
    const controller = new AbortController();
    const receive = async () => {
      let retryDelay = 1500;
      while (!controller.signal.aborted) {
        try {
          await client.events((msg) => {
            setFollowStatus("connected");
            retryDelay = 1500;
            if (msg.type === "screen_ea" && msg.ea) navRef.current(msg.ea, false);
            else if (msg.type === "view" && msg.view && (TABS as string[]).includes(msg.view)) showTabRef.current(msg.view as Tab);
          }, controller.signal);
          if (!controller.signal.aborted) setFollowStatus("reconnecting");
        } catch (eventError) {
          if (controller.signal.aborted) break;
          if (eventError instanceof HttpError && (eventError.status === 401 || eventError.status === 403)) {
            setFollow(false);
            setError("Follow IDA stopped: the token is no longer accepted. Reconnect with the current token.");
            break;
          }
          setFollowStatus("reconnecting");
        }
        if (!controller.signal.aborted) {
          await new Promise((resolve) => window.setTimeout(resolve, retryDelay));
          retryDelay = Math.min(retryDelay * 2, 30_000);
        }
      }
    };
    void receive();
    return () => controller.abort();
  }, [follow, client]);

  // Keyboard shortcuts: Ctrl-K or "/" opens search; N renames in Drive mode.
  useEffect(() => {
    function onKey(e: globalThis.KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen(true);
        return;
      }
      const el = document.activeElement;
      if (el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA")) return;
      if (e.key === "/") {
        e.preventDefault();
        setPaletteOpen(true);
      } else if (e.key.toLowerCase() === "n" && drive && info?.allow_write && selected) {
        e.preventDefault();
        renameFunction();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [drive, selected, client]);

  async function loadHexAt(addrText: string) {
    if (!client) return;
    const activeClient = client;
    const generation = ++hexGeneration.current;
    const ea = toHex(addrText.trim());
    try {
      BigInt(ea);
    } catch {
      return; // not a valid address
    }
    try {
      const result = await client.hex(ea, 2048);
      if (clientRef.current === activeClient && hexGeneration.current === generation) setHexData(result);
    } catch (e) {
      if (clientRef.current === activeClient && hexGeneration.current === generation) setError(`Load failed: ${(e as Error).message}`);
    }
  }

  async function showStringXrefs(ea: Ea) {
    if (!client) return;
    const activeClient = client;
    const generation = ++stringXrefGeneration.current;
    try {
      const items = await client.xrefs(ea);
      if (clientRef.current === activeClient && stringXrefGeneration.current === generation) {
        setStrXrefs({ ea, items: items.items, truncated: items.truncated });
      }
    } catch (e) {
      if (clientRef.current === activeClient && stringXrefGeneration.current === generation) setError(`Load failed: ${(e as Error).message}`);
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
    if (drive && client) {
      client
        .goto(ea)
        .then((result) => {
          if (!result.ok) setError(`IDA could not jump to ${toHex(ea)}.`);
        })
        .catch((driveError) => setError(`Drive IDA failed: ${(driveError as Error).message}`));
    }
  }

  async function renameFunction() {
    if (!client || !selected) return;
    const activeClient = client;
    const target = selected;
    const generation = selectionGeneration.current;
    const name = window.prompt("Rename function", target.name);
    if (name === null || name === target.name) return;
    try {
      const result = await client.rename(target.ea, name);
      if (!result.ok) throw new Error("IDA rejected the new name");
      const fns = await client.functions();
      if (clientRef.current !== activeClient) return;
      setFunctions(fns);
      if (selectionGeneration.current !== generation || selectedRef.current?.ea !== target.ea) return;
      const updatedDisasm = await client.disasm(target.ea);
      const updatedPseudo = tab === "pseudo" && info?.has_hexrays ? await client.pseudocode(target.ea) : null;
      if (clientRef.current !== activeClient || selectionGeneration.current !== generation || selectedRef.current?.ea !== target.ea) return;
      setSelected(fns.find((f) => f.ea === target.ea) ?? target);
      setDisasm(updatedDisasm);
      if (updatedPseudo) setPseudo(updatedPseudo);
    } catch (e) {
      setError(`Rename failed: ${(e as Error).message}`);
    }
  }

  async function setCommentAt(ea: Ea) {
    if (!client || !selected) return;
    const activeClient = client;
    const target = selected;
    const generation = selectionGeneration.current;
    const text = window.prompt(`Comment at ${toHex(ea)}`, "");
    if (text === null) return;
    try {
      const result = await client.comment(ea, text);
      if (!result.ok) throw new Error("IDA rejected the comment");
      const updated = await client.disasm(target.ea);
      if (clientRef.current === activeClient && selectionGeneration.current === generation && selectedRef.current?.ea === target.ea) setDisasm(updated);
    } catch (e) {
      setError(`Comment failed: ${(e as Error).message}`);
    }
  }

  async function renameLvar(oldName: string) {
    if (!client || !selected) return;
    const activeClient = client;
    const target = selected;
    const generation = selectionGeneration.current;
    const name = window.prompt(`Rename variable "${oldName}"`, oldName);
    if (name === null || !name.trim() || name === oldName) return;
    try {
      const res = await client.renameLvar(target.ea, oldName, name.trim());
      if (!res.ok) {
        setError(`Rename failed — variable "${oldName}" not found`);
        return;
      }
      const updated = await client.pseudocode(target.ea);
      if (clientRef.current === activeClient && selectionGeneration.current === generation && selectedRef.current?.ea === target.ea) setPseudo(updated);
    } catch (e) {
      setError(`Rename failed: ${(e as Error).message}`);
    }
  }

  async function showTab(next: Tab) {
    setTab(next);
    if (!client) return;
    const activeClient = client;
    const functionEa = selectedRef.current?.ea;
    const generation = ++tabGeneration.current;
    const isCurrent = () => clientRef.current === activeClient && tabGeneration.current === generation;
    try {
      if (next === "graph" && graph === null && functionEa) {
        const result = await client.graph(functionEa);
        if (isCurrent() && selectedRef.current?.ea === functionEa) setGraph(result);
      }
      if (next === "pseudo" && pseudo === null && functionEa && info?.has_hexrays) {
        const result = await client.pseudocode(functionEa);
        if (isCurrent() && selectedRef.current?.ea === functionEa) setPseudo(result);
      }
      if (next === "strings" && strings === null) {
        const result = await client.strings();
        if (isCurrent()) {
          setNames(null);
          setStrings(result);
        }
      }
      if (next === "imports" && imports === null) {
        const result = await client.imports();
        if (isCurrent()) setImports(result);
      }
      if (next === "exports" && exports === null) {
        const result = await client.exports();
        if (isCurrent()) setExports(result);
      }
      if (next === "segments" && segments === null) {
        const result = await client.segments();
        if (isCurrent()) setSegments(result);
      }
      if (next === "names" && names === null) {
        const result = await client.names();
        if (isCurrent()) {
          setStrings(null);
          setStrXrefs(null);
          setNames(result);
        }
      }
      if (next === "types" && localTypes === null) {
        const result = await client.localTypes();
        if (result.error) throw new Error(`Local types: ${result.error}`);
        if (isCurrent()) setLocalTypes(result.items);
      }
      if (next === "hex" && hexData === null) await loadHexAt(hexAddr || info?.image_base || "0");
    } catch (e) {
      if (isCurrent()) setError(`Load failed: ${(e as Error).message}`);
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

  const highlightedDisassemblyIndex = useMemo(
    () => (highlightEa && disasm ? disasm.lines.findIndex((line) => line.ea === highlightEa) : -1),
    [disasm, highlightEa],
  );

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
          <div className="token-row">
            <input
              type={tokenVisible ? "text" : "password"}
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="token"
              autoComplete="off"
              spellCheck={false}
            />
            <button type="button" className="token-toggle" onClick={() => setTokenVisible((visible) => !visible)}>
              {tokenVisible ? "Hide" : "Show"}
            </button>
          </div>
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
        <button className="search-btn" onClick={() => setPaletteOpen(true)} title="Search (Ctrl-K)">
          Search <span className="kbd">Ctrl-K</span>
        </button>
        <select className="theme-select" value={theme} onChange={(e) => setTheme(e.target.value)} title="Theme">
          <option value="dark">Dark</option>
          <option value="darcula">Darcula</option>
          <option value="light">Light</option>
        </select>
        <button className={follow ? "follow on" : "follow"} onClick={() => setFollow((f) => !f)} title="Follow IDA's current address">
          {follow ? (followStatus === "reconnecting" ? "○ Reconnecting" : "● Following") : "Follow"}
        </button>
        <button
          className={drive ? "follow on" : "follow"}
          onClick={() => setDrive((d) => !d)}
          title={info.allow_write ? "Send clicks to IDA and enable write-back" : "Send clicks to IDA (write-back is disabled on the server)"}
        >
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
                {drive && info.allow_write && (
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
            disasm ? (
              <VirtualList
                className="view mono code-list"
                items={disasm.lines}
                rowHeight={24}
                scrollToIndex={highlightedDisassemblyIndex >= 0 ? highlightedDisassemblyIndex : undefined}
                renderRow={(line) => {
                  const flashing = line.ea === highlightEa;
                  return (
                    <div
                      className={`codeline ${flashing ? "flash" : ""}`}
                      key={line.ea}
                      ref={flashing ? flashRef : undefined}
                      onAnimationEnd={flashing ? () => setHighlightEa(null) : undefined}
                    >
                      <span
                        className={`dim ${drive && info.allow_write ? "addr-edit" : ""}`}
                        onClick={drive && info.allow_write ? () => setCommentAt(line.ea) : undefined}
                        title={drive && info.allow_write ? "Add / edit comment" : undefined}
                      >
                        {toHex(line.ea)}
                      </span>{" "}
                      {renderTokens(line.tokens, navigateToAddress)}
                    </div>
                  );
                }}
              />
            ) : (
              <div className="view dim">Loading...</div>
            )
          )}

          {tab === "graph" &&
            selected &&
            (graph ? (
              <GraphView graph={graph} onNavigate={navigateToAddress} />
            ) : (
              <div className="view dim">Loading...</div>
            ))}

          {tab === "pseudo" && selected && (
            pseudo ? (
              <VirtualList
                className="view mono code-list"
                items={pseudo.lines}
                rowHeight={24}
                renderRow={(line, index) => (
                  <div className="codeline" key={index}>
                    {renderTokens(line.tokens, navigateToAddress, drive && info.allow_write ? renameLvar : undefined)}
                  </div>
                )}
              />
            ) : (
              <div className="view dim">Loading...</div>
            )
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
                items={strings === null ? null : visibleStrings}
                renderRow={(item) => [toHex(item.ea), String(item.length), item.text]}
                getAddress={(item) => item.ea}
                onNavigate={showStringXrefs}
                onActivate={goToHexAt}
                selectedAddress={strXrefs?.ea}
              />
              {strXrefs && (
                <div className="xrefs">
                  <div className="dim">
                    Xrefs to <span className="mono">{toHex(strXrefs.ea)}</span> ({strXrefs.items.length}) ·{" "}
                    <span className="ref" onClick={() => goToHexAt(strXrefs.ea)}>
                      open in Hex
                    </span>
                  </div>
                  {strXrefs.truncated && <div className="dim">Showing the first {strXrefs.items.length} references.</div>}
                  {strXrefs.items.length === 0 && <div className="dim">no cross-references</div>}
                  <VirtualList
                    className="xref-list"
                    items={strXrefs.items}
                    rowHeight={24}
                    renderRow={(x, index) => (
                      <div className="xref mono ref" key={`${x.frm}-${index}`} onClick={() => navigateToAddress(x.frm)}>
                        <span className="dim">{toHex(x.frm)}</span> {x.name || "—"}
                      </div>
                    )}
                  />
                </div>
              )}
            </>
          )}
          {tab === "names" && (
            <DataTable
              columns={["Address", "Name"]}
              template="15ch 1fr"
              items={names}
              renderRow={(item) => [toHex(item.ea), item.name]}
              getAddress={(item) => item.ea}
              onNavigate={navigateToAddress}
            />
          )}
          {tab === "imports" && (
            <DataTable
              columns={["Address", "Module", "Name", "Ordinal"]}
              template="15ch 12ch 1fr 7ch"
              items={imports}
              renderRow={(item) => [toHex(item.ea), item.module, item.name || "(ordinal)", item.ordinal ? String(item.ordinal) : ""]}
              getAddress={(item) => item.ea}
              onNavigate={navigateToAddress}
            />
          )}
          {tab === "exports" && (
            <DataTable
              columns={["Address", "Ordinal", "Name"]}
              template="15ch 7ch 1fr"
              items={exports}
              renderRow={(item) => [toHex(item.ea), String(item.ordinal), item.name]}
              getAddress={(item) => item.ea}
              onNavigate={navigateToAddress}
            />
          )}
          {tab === "segments" && (
            <DataTable
              columns={["Name", "Start", "End", "Class", "Perm"]}
              template="1fr 15ch 15ch 9ch 6ch"
              items={segments}
              renderRow={(item) => [item.name, toHex(item.start), toHex(item.end), item.class, String(item.perm)]}
              getAddress={(item) => item.start}
              onNavigate={navigateToAddress}
            />
          )}
          {tab === "types" && (
            <DataTable
              columns={["Ordinal", "Name", "Declaration"]}
              template="7ch 1fr 2fr"
              items={localTypes}
              renderRow={(item) => [String(item.ordinal), item.name, item.decl]}
            />
          )}

          {(tab === "disasm" || tab === "pseudo") && selected && xrefs.length > 0 && (
            <div className="xrefs">
              <div className="dim">Cross-references ({xrefs.length})</div>
              {xrefsTruncated && <div className="dim">Showing the first {xrefs.length} references.</div>}
              <VirtualList
                className="xref-list"
                items={xrefs}
                rowHeight={24}
                renderRow={(x, index) => (
                  <div className="xref mono ref" key={`${x.frm}-${index}`} onClick={() => navigateToAddress(x.frm)}>
                    <span className="dim">{toHex(x.frm)}</span> {x.name || "—"}
                  </div>
                )}
              />
            </div>
          )}
        </main>
      </div>

      {paletteOpen && client && (
        <CommandPalette client={client} onNavigate={navigateToAddress} onClose={() => setPaletteOpen(false)} />
      )}
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

function DataTable<T>(props: {
  columns: string[];
  template: string;
  items: T[] | null;
  renderRow: (item: T) => string[];
  getAddress?: (item: T) => Ea;
  onNavigate?: (addr: Ea) => void;
  onActivate?: (addr: Ea) => void;
  selectedAddress?: Ea;
}) {
  if (props.items === null) return <div className="view dim">Loading...</div>;
  const interactive = props.getAddress && (props.onNavigate || props.onActivate);
  return (
    <div className="dtable mono">
      <div className="dthead" style={{ gridTemplateColumns: props.template }}>
        {props.columns.map((c) => (
          <div key={c}>{c}</div>
        ))}
      </div>
      <VirtualList
        className="dtbody"
        items={props.items}
        rowHeight={24}
        renderRow={(item, i) => {
          const row = props.renderRow(item);
          const addr = props.getAddress?.(item);
          return (
            <div
              key={addr ?? i}
              className={`dtrow ${interactive ? "clickable" : ""} ${props.selectedAddress === addr ? "active" : ""}`}
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

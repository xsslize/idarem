// Typed client for the idarem plugin's HTTP API.

// Addresses travel as hex strings ("0x140001000"): a 64-bit address can exceed
// JavaScript's 2**53 safe-integer range, so a JSON number would lose precision.
export type Ea = string;

export interface Info {
  file: string;
  processor: string;
  bits: number;
  image_base: Ea;
  has_hexrays: boolean;
}

export interface FunctionEntry {
  ea: Ea;
  name: string;
  size: number;
}

// One colored span of a code line: text plus an IDA color category. In
// pseudocode, `lv` is set to the local-variable name when the token is one.
export interface Token {
  t: string;
  c: string;
  lv?: string;
}

export interface DisasmLine {
  ea: Ea;
  tokens: Token[];
}

export interface Disassembly {
  ea: Ea;
  name: string;
  lines: DisasmLine[];
}

export interface GraphBlock {
  id: number;
  start: Ea;
  end: Ea;
  lines: DisasmLine[];
}

export interface GraphEdge {
  src: number;
  dst: number;
  kind: "true" | "false" | "uncond";
}

export interface Graph {
  ea: Ea;
  name: string;
  blocks: GraphBlock[];
  edges: GraphEdge[];
}

export interface PseudoLine {
  tokens: Token[];
}

export interface Pseudocode {
  ea: Ea;
  name: string;
  lines: PseudoLine[];
}

export interface Xref {
  frm: Ea;
  name: string;
  is_call: boolean;
}

export interface StringItem {
  ea: Ea;
  length: number;
  text: string;
}

export interface ImportItem {
  ea: Ea;
  module: string;
  name: string;
  ordinal: number;
}

export interface ExportItem {
  ea: Ea;
  ordinal: number;
  name: string;
}

export interface HexResult {
  ea: Ea;
  hex: string;
}

export interface SegmentItem {
  start: Ea;
  end: Ea;
  name: string;
  class: string;
  perm: number;
}

export interface NameItem {
  ea: Ea;
  name: string;
}

export interface LocalType {
  ordinal: number;
  name: string;
  decl: string;
}

export interface LocalTypesResult {
  items: LocalType[];
  error?: string;
}

export type SearchKind = "address" | "function" | "string" | "name";

export interface SearchResult {
  kind: SearchKind;
  ea: Ea;
  label: string;
}

export class ApiClient {
  private baseUrl: string;
  private token: string;

  constructor(baseUrl: string, token: string) {
    this.baseUrl = baseUrl;
    this.token = token;
  }

  private async get<T>(path: string): Promise<T> {
    const headers: Record<string, string> = {};
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
    const response = await fetch(`${this.baseUrl}${path}`, { headers });
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    return (await response.json()) as T;
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
    const response = await fetch(`${this.baseUrl}${path}`, { method: "POST", headers, body: JSON.stringify(body) });
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    return (await response.json()) as T;
  }

  info() {
    return this.get<Info>("/api/info");
  }
  functions() {
    return this.get<FunctionEntry[]>("/api/functions");
  }
  disasm(ea: Ea) {
    return this.get<Disassembly>(`/api/disasm/${ea}`);
  }
  graph(ea: Ea) {
    return this.get<Graph>(`/api/graph/${ea}`);
  }
  pseudocode(ea: Ea) {
    return this.get<Pseudocode>(`/api/pseudocode/${ea}`);
  }
  xrefs(ea: Ea) {
    return this.get<Xref[]>(`/api/xrefs/${ea}`);
  }
  strings() {
    return this.get<StringItem[]>("/api/strings");
  }
  imports() {
    return this.get<ImportItem[]>("/api/imports");
  }
  exports() {
    return this.get<ExportItem[]>("/api/exports");
  }
  hex(ea: Ea, count = 1024) {
    return this.get<HexResult>(`/api/hex/${ea}?count=${count}`);
  }
  segments() {
    return this.get<SegmentItem[]>("/api/segments");
  }
  names() {
    return this.get<NameItem[]>("/api/names");
  }
  localTypes() {
    return this.get<LocalTypesResult>("/api/local-types");
  }
  search(query: string, limit = 60) {
    return this.get<SearchResult[]>(`/api/search?q=${encodeURIComponent(query)}&limit=${limit}`);
  }
  // EventSource can't send headers, so the token rides as a query param.
  eventsUrl() {
    const q = this.token ? `?token=${encodeURIComponent(this.token)}` : "";
    return `${this.baseUrl}/api/events${q}`;
  }

  // Write-back commands (web -> IDA).
  goto(ea: Ea) {
    return this.post<{ ok: boolean }>("/api/goto", { ea });
  }
  rename(ea: Ea, name: string) {
    return this.post<{ ok: boolean; name: string }>("/api/rename", { ea, name });
  }
  comment(ea: Ea, text: string) {
    return this.post<{ ok: boolean }>("/api/comment", { ea, text });
  }
  renameLvar(ea: Ea, old: string, name: string) {
    return this.post<{ ok: boolean }>("/api/rename-lvar", { ea, old, new: name });
  }
}

// Normalize a user-typed or server-sent address to a canonical "0x…" string.
export const toHex = (ea: Ea): string => {
  try {
    return "0x" + BigInt(ea.startsWith("0x") || ea.startsWith("0X") ? ea : "0x" + ea).toString(16).toUpperCase();
  } catch {
    return ea;
  }
};

// Address + byte offset, returned as a canonical hex string (64-bit safe).
export const eaAdd = (ea: Ea, delta: number): string => "0x" + (BigInt(ea) + BigInt(delta)).toString(16).toUpperCase();

// Names like sub_140001370 / loc_140001380 encode their target address.
export const NAME_REF = /^(?:sub|loc|locret|j|nullsub|def)_([0-9A-Fa-f]+)$/;

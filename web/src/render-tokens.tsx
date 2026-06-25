import { type ReactNode } from "react";
import { NAME_REF, type Token } from "./api";

// Render IDA's colored tokens; sub_/loc_ names become clickable navigation links.
export function renderTokens(tokens: Token[], onNavigate: (addr: string) => void): ReactNode[] {
  return tokens.map((token, i) => {
    const match = token.t.match(NAME_REF);
    if (match) {
      return (
        <span key={i} className={`tok-${token.c} ref`} onClick={() => onNavigate("0x" + match[1])}>
          {token.t}
        </span>
      );
    }
    return (
      <span key={i} className={`tok-${token.c}`}>
        {token.t}
      </span>
    );
  });
}

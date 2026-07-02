import { type ReactNode } from "react";
import { NAME_REF, type Token } from "./api";

// Render IDA's colored tokens. sub_/loc_ names are clickable navigation links;
// when onRenameLvar is given (pseudocode in Drive mode), tokens the decompiler
// marked as a local variable (token.lv) become clickable to rename.
export function renderTokens(
  tokens: Token[],
  onNavigate: (addr: string) => void,
  onRenameLvar?: (name: string) => void,
): ReactNode[] {
  return tokens.map((token, i) => {
    const match = token.t.match(NAME_REF);
    if (match) {
      return (
        <span key={i} className={`tok-${token.c} ref`} onClick={() => onNavigate("0x" + match[1])}>
          {token.t}
        </span>
      );
    }
    if (onRenameLvar && token.lv) {
      const name = token.lv;
      return (
        <span key={i} className={`tok-${token.c} ref`} onClick={() => onRenameLvar(name)}>
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

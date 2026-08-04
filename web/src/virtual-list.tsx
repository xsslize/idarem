import { useEffect, useRef, useState, type ReactNode } from "react";

// Fixed-height row virtualizer: only the rows currently in view are mounted, so
// a 50k-row list costs the same DOM as a screenful. Every row must be exactly
// `rowHeight` tall.
export function VirtualList<T>({
  items,
  rowHeight,
  className,
  renderRow,
  scrollToIndex,
}: {
  items: T[];
  rowHeight: number;
  className?: string;
  renderRow: (item: T, index: number) => ReactNode;
  scrollToIndex?: number;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewport, setViewport] = useState(0);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const measure = () => setViewport(el.clientHeight);
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    setScrollTop(0);
    if (ref.current) ref.current.scrollTop = 0;
  }, [items]);

  useEffect(() => {
    const el = ref.current;
    if (!el || scrollToIndex === undefined || scrollToIndex < 0 || scrollToIndex >= items.length) return;
    const next = Math.max(0, scrollToIndex * rowHeight - (el.clientHeight - rowHeight) / 2);
    el.scrollTop = next;
    setScrollTop(next);
  }, [items, rowHeight, scrollToIndex]);

  const total = items.length;
  const overscan = 8;
  const start = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
  const visible = Math.ceil((viewport || rowHeight) / rowHeight) + overscan * 2;
  const end = Math.min(total, start + visible);

  const rows: ReactNode[] = [];
  for (let i = start; i < end; i++) rows.push(renderRow(items[i], i));

  return (
    <div className={className} ref={ref} onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)} style={{ overflowY: "auto" }}>
      <div style={{ height: total * rowHeight, position: "relative" }}>
        <div style={{ position: "absolute", top: 0, left: 0, right: 0, transform: `translateY(${start * rowHeight}px)` }}>{rows}</div>
      </div>
    </div>
  );
}

// Collapsible protocol dissection tree (from tshark PDML).
import { useEffect, useMemo, useRef } from "react";
import type { TreeNode } from "../api";
import { usePersist } from "../ui";

export interface Flat { node: TreeNode; path: string; depth: number; hasKids: boolean; open: boolean; isProto: boolean }

export function flatten(nodes: TreeNode[], open: Set<string>, prefix = "", depth = 0, out: Flat[] = []): Flat[] {
  nodes.forEach((n, i) => {
    const path = prefix + i;
    const hasKids = !!n.children?.length;
    const key = n.field || n.label;
    const isOpen = hasKids && (open.has(path) || open.has("f:" + key));
    out.push({ node: n, path, depth, hasKids, open: isOpen, isProto: depth === 0 });
    if (isOpen) flatten(n.children!, open, path + ".", depth + 1, out);
  });
  return out;
}

/** Finds the path of the deepest verified node covering byte offset b. */
export function pathForByte(nodes: TreeNode[], b: number, prefix = ""): string | null {
  for (let i = 0; i < nodes.length; i++) {
    const n = nodes[i];
    if (n.verified && b >= n.pos && b < n.pos + n.size && n.field !== "frame") {
      const deeper = n.children ? pathForByte(n.children, b, prefix + i + ".") : null;
      return deeper ?? prefix + i;
    }
    if (n.field === "frame" || !n.verified) {
      const d = n.children ? pathForByte(n.children, b, prefix + i + ".") : null;
      if (d) return d;
    }
  }
  return null;
}

export function nodeAt(nodes: TreeNode[], path: string): TreeNode | undefined {
  let cur: TreeNode | undefined;
  let list: TreeNode[] | undefined = nodes;
  for (const i of path.split(".")) { cur = list?.[+i]; list = cur?.children; }
  return cur;
}

interface Props { tree: TreeNode[]; selected: string; onSelect: (path: string) => void; onContext: (n: TreeNode, e: React.MouseEvent) => void }

export default function ProtoTree({ tree, selected, onSelect, onContext }: Props) {
  // Expanded subtrees are remembered by field name across packets, like Wireshark.
  const [openList, setOpenList] = usePersist<string[]>("tree.open", []);
  const open = useMemo(() => {
    const s = new Set(openList);
    // make sure the selected node's ancestors are open
    const parts = selected.split(".");
    for (let i = 1; i < parts.length; i++) s.add(parts.slice(0, i).join("."));
    return s;
  }, [openList, selected]);
  const flat = flatten(tree, open);
  const ref = useRef<HTMLDivElement>(null);

  const toggle = (f: Flat, to = !f.open) => {
    const key = "f:" + (f.node.field || f.node.label);
    setOpenList((l) => {
      const s = new Set(l);
      s.delete(f.path);
      if (to) s.add(key); else s.delete(key);
      return [...s].slice(-400);
    });
  };

  useEffect(() => { ref.current?.querySelector(".tn.sel")?.scrollIntoView({ block: "nearest" }); }, [selected]);

  const onKey = (e: React.KeyboardEvent) => {
    const i = flat.findIndex((f) => f.path === selected);
    const f = flat[i];
    if (e.key === "ArrowDown" && i < flat.length - 1) onSelect(flat[i + 1].path);
    else if (e.key === "ArrowUp" && i > 0) onSelect(flat[i - 1].path);
    else if (e.key === "ArrowRight" && f?.hasKids && !f.open) toggle(f, true);
    else if (e.key === "ArrowLeft" && f) { if (f.open) toggle(f, false); else if (f.depth) onSelect(f.path.split(".").slice(0, -1).join(".")); }
    else if (e.key === "Enter" && f?.hasKids) toggle(f);
    else return;
    e.preventDefault();
  };

  return (
    <div className="tree" ref={ref} tabIndex={0} role="tree" aria-label="Protocol tree" onKeyDown={onKey}>
      {flat.map((f) => (
        <div key={f.path} role="treeitem" aria-expanded={f.hasKids ? f.open : undefined} aria-selected={f.path === selected}
          className={"tn" + (f.path === selected ? " sel" : "")} style={{ paddingLeft: 6 + f.depth * 16 }}
          onMouseDown={() => onSelect(f.path)} onDoubleClick={() => f.hasKids && toggle(f)}
          onContextMenu={(e) => { e.preventDefault(); onSelect(f.path); onContext(f.node, e); }}
          title={f.node.field ? `${f.node.field}${f.node.size ? ` · ${f.node.size} byte(s) at offset ${f.node.pos}` : ""}` : undefined}>
          <span className="tw" onMouseDown={(e) => { e.stopPropagation(); if (f.hasKids) toggle(f); }}>{f.hasKids ? (f.open ? "▾" : "▸") : ""}</span>
          <span className={f.isProto ? "proto" : "fld"}>{f.node.label}</span>
          {f.path === selected && f.node.size > 0 && !f.node.verified && <span className="nomap">byte range not verifiable (reassembled or generated data)</span>}
        </div>
      ))}
    </div>
  );
}

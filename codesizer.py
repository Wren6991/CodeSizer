#!/usr/bin/env python3
"""Analyse static code size of an ELF file.

Disassemble via objdump, unwind inline call stacks via addr2line, and emit a static HTML report."""

import argparse
import bisect
import html
import itertools
import os
import re
import subprocess
import sys

# -----------------------------------------------------------------------------
# Tool wrappers

def run(cmd, stdin_bytes=None):
    proc = subprocess.run(
        cmd,
        input=stdin_bytes,
        capture_output=True,
        check=True,
    )
    return proc.stdout.decode("utf-8", errors="replace")

def objdump_disasm(prefix, elf, sections=[".text"]):
    args = [prefix + "objdump", "-d", elf]
    for section in sections:
        args.extend(["-j", section])
    return run(args)

def objdump_symbols(prefix, elf, sections=[".text"]):
    args = [prefix + "objdump", "-t", elf]
    for section in sections:
        args.extend(["-j", section])
    return run(args)

def addr2line_batch(prefix, elf, addresses):
    """ Returns dict: addr -> list of (name, file, line) tuples,
     listed from innermost to outermost."""
    stdin = "".join(f"{a:x}\n" for a in addresses).encode("ascii")
    out = run([prefix + "addr2line", "-fairC", "--exe", elf], stdin_bytes=stdin)
    return parse_addr2line(out)

# -------------------------------------------------------------------------------
# Parsers

# Note some arches like to put spaces between halfwords or bytes
_ADDR_LINE_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{2,}(?: [0-9a-fA-F]{2,})*)\s+")

def parse_instructions(disasm):
    """Parse objdump -d output into a list of (address, size) tuples."""
    result = []
    for line in disasm.splitlines():
        m = _ADDR_LINE_RE.match(line)
        if not m: continue
        addr = int(m.group(1), 16)
        nbytes = sum(c != " " for c in m.group(2)) // 2
        result.append((addr, nbytes))
    return result

_ADDR2LINE_ADDR_RE = re.compile(r"^0x([0-9a-fA-F]+)\s*$")
# Junk that addr2line adds because it's in the DWARF info, we don't care:
_DISCRIMINATOR_RE = re.compile(r"\s*\(discriminator \d+\)")

def parse_addr2line(output):
    """Parse the output of `addr2line -fairC`"""
    lines = output.splitlines()
    stacks = {}
    i = 0
    n = len(lines)
    while i < n:
        m = _ADDR2LINE_ADDR_RE.match(lines[i])
        if not m:
            i += 1
            continue
        addr = int(m.group(1), 16)
        i += 1
        frames = []
        while i < n and not _ADDR2LINE_ADDR_RE.match(lines[i]):
            name = lines[i]
            i += 1
            if i < n and not _ADDR2LINE_ADDR_RE.match(lines[i]):
                fileline = lines[i]
                i += 1
            else:
                fileline = "??:0"
            fileline = _DISCRIMINATOR_RE.sub("", fileline)
            if ":" in fileline:
                file, _, line = fileline.rpartition(":")
            else:
                file, line = split_file_line(fileline)
            frames.append((name, file, line))
        stacks[addr] = frames
    return stacks

def strip_common_path_prefix(stacks):
    paths = {file for frames in stacks.values() for _, file, _ in frames if "/" in file}

    if not paths:
        return
    prefix = os.path.commonprefix(list(paths))
    for addr, frames in stacks.items():
        stacks[addr] = [
            (name, file[len(prefix):] if file.startswith(prefix) else file, line)
            for (name, file, line) in frames
        ]

# For flag descriptions see: https://man7.org/linux/man-pages/man1/objdump.1.html
# Mainly we care about global (g) and function (F)
_SYM_RE = re.compile(
    r"^([0-9a-fA-F]+) ([lgu! ][w ][C ][W ][Ii ][Dd ][FfO ]) ([\.\$\w\d]+)\t([0-9a-fA-F]+)\s+(\S.*?)\s*$"
)

def parse_symbols(symtab):
    """Parse `objdump -t` output for function symbols.

    Returns list of dicts: {name, addr, size}.
    """
    syms = []
    for line in symtab.splitlines():
        m = _SYM_RE.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        section = m.group(3)
        flags = m.group(2)
        # We actually ignore size since it seems to be 0 for asm symbols
        size = int(m.group(4), 16)
        name = m.group(5).strip()
        # Asm symbols might have weird flags -- forgot to mark as function, or
        # non-global function. Include both.
        is_func = "g" in flags or "F" in flags
        if not is_func: continue
        # print(f"{section} [{flags}] {size}: {name}")
        if name.startswith(".hidden "):
            name = name[len(".hidden "):]
        syms.append({"name": name, "addr": addr, "size": size})
    # Deduplicate by addr (keep first); sort by addr.
    seen = set()
    unique = []
    for s in sorted(syms, key=lambda s: (s["addr"], -s["size"])):
        if s["addr"] in seen:
            continue
        seen.add(s["addr"])
        unique.append(s)
    return unique

# -----------------------------------------------------------------------------
# Tree building

class Node:
    __slots__ = ("name", "file", "line", "self_size", "cum", "children")

    def __init__(self, name, file, line):
        self.name = name
        self.file = file
        self.line = line
        self.self_size = 0
        self.cum = 0
        self.children = {}

def build_symbol_tree(symbol, addrs, addr_stack, instr_by_addr):
    """Build an inline-callee tree for one symbol.

    addrs: sorted list of addresses within [symbol.addr, symbol.addr+size)
        that have addr2line stacks.
    addr_stack: dict addr -> list of (name, file, line) innermost-first.
    instr_by_addr: dict addr -> size.

    Children are keyed by (name, file), since inline names can be re-used
    across source TUs.
    """
    root = Node(symbol["name"], "", "")
    for addr in addrs:
        stack = addr_stack[addr]
        size = instr_by_addr[addr]
        # Walk outermost -> innermost. The outermost frame should match the
        # containing symbol; if it does, drop it (it's the root). Otherwise we
        # still attach under the symbol root so no bytes are lost.
        frames = list(reversed(stack))
        # The outermost frame of the lowest address in the symbol is the
        # symbol's own source location; capture it on the first iteration.
        if not root.file and frames:
            root.file = frames[0][1]
            root.line = frames[0][2]
        if frames and frames[0][0] == root.name:
            frames = frames[1:]
        node = root
        node.cum += size
        for (name, file, line) in frames:
            key = (name, file)
            child = node.children.get(key)
            if child is None:
                child = Node(name, file, line)
                node.children[key] = child
            child.cum += size
            node = child
        # Leaf: attribute self bytes to the deepest reached node. If frames
        # was empty (no inlining, outermost matched symbol), the leaf is root.
        node.self_size += size
    return root

def sort_children(node):
    """Recursively sort children by cumulative size descending."""
    node.children = {
        k: v for k, v in
        sorted(node.children.items(), key=lambda kv: kv[1].cum, reverse=True)
    }
    for c in node.children.values():
        sort_children(c)

# -----------------------------------------------------------------------------
# HTML rendering

CSS = """
* { box-sizing: border-box; }
/* Colour scheme: Solarized Dark/Light depending on user preference */
:root {
  --bg: #002b36;            /* main background */
  --bg-panel: #073642;      /* elevated panels (header, tabs, headers) */
  --bg-hover: #073642;      /* row hover */
  --border: #586e75;        /* visible borders */
  --border-subtle: #073642; /* subtle row dividers */
  --text: #93a1a1;          /* body text */
  --text-bright: #fdf6e3;   /* active/emphasis text */
  --text-dim: #839496;      /* secondary text */
  --accent-blue: #268bd2;   /* headers, leaf functions */
  --accent-yellow: #b58900; /* function names */
  --accent-cyan: #2aa198;   /* symbols, links */
  --accent-orange: #cb4b16; /* self size, code */
  --accent-green: #859900;  /* cumulative size */

  --font-default: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --font-mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg: #fdf6e3;
    --bg-panel: #eee8d5;
    --bg-hover: #eee8d5;
    --border: #93a1a1;
    --border-subtle: #eee8d5;
    --text: #657b83;
    --text-bright: #073642;
    --text-dim: #586e75;
  }
}
body { font-family: var(--font-default); margin: 0; background: var(--bg); color: var(--text); height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
header { padding: 12px 20px; background: var(--bg-panel); border-bottom: 1px solid var(--border); flex: 0 0 auto; }
h1 { margin: 0; font-size: 14px; font-weight: 500; font-family: var(--font-mono); }
.tabs { display: flex; gap: 4px; padding: 8px 20px 0 20px; background: var(--bg-panel); flex: 0 0 auto; }
.tab { padding: 8px 14px; cursor: pointer; border: 1px solid var(--border); border-bottom: none; background: var(--bg-panel); color: var(--text-dim); border-radius: 4px 4px 0 0; user-select: none; font-size: 13px; }
.tab.active { background: var(--bg); color: var(--text-bright); border-color: var(--border); }
#content { flex: 1 1 auto; overflow: hidden; }
.tab-page { display: none; height: 100%; overflow-y: auto; padding: 0 20px 16px; }
.tab-page.active { display: block; }
.summary { color: var(--text-dim); font-size: 12px; margin: 16px 0 12px 0; }
table { border-collapse: collapse; width: 100%; font-size: 12px; }
th, td { text-align: left; padding: 3px 6px; white-space: nowrap; }
th { color: var(--accent-blue); background: var(--bg-panel); position: sticky; top: 0; cursor: pointer; }
th.num, td.num { text-align: right; font-variant-numeric: tabular-nums; }
tr:hover td { background: var(--bg-hover); }

/* ---- Tree (tab 1) ---- */
.tree-header, .tree-row { display: flex; align-items: center; gap: 8px; padding: 3px 6px; }
.tree-header { color: var(--accent-blue); background: var(--bg-panel); position: sticky; top: 0; z-index: 5; font-size: 12px; }
.tree-row { cursor: default; border-bottom: 1px solid var(--border-subtle); }
.tree-row:hover { background: var(--bg-hover); }
.tree-row.clickable { cursor: pointer; }
.col-name { flex: 1 1 auto; min-width: 120px; display: flex; align-items: center; gap: 4px; padding-left: calc(var(--depth, 0) * 16px); white-space: nowrap; overflow: hidden; }
.col-loc { flex: 0 0 640px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; direction: rtl; text-align: left; color: var(--text-dim); font-size: 12px; }
.col-disasm { flex: 0 0 64px; text-align: center; color: var(--text-dim); font-size: 12px;}
.col-self, .col-cum, .col-pct { flex: 0 0 64px; text-align: right; font-variant-numeric: tabular-nums; }
.col-pct { flex: 0 0 64px; color: var(--text-dim); }
.tree-name { color: var(--accent-yellow); overflow: hidden; text-overflow: ellipsis; }
.tree-name.leaf { color: var(--accent-blue); }
.tree-arrow { display: inline-block; width: 2em; text-align: center; font-size: 12px;}
.symbol-name { color: var(--accent-cyan); font-weight: 500; }
.col-self { color: var(--accent-orange); }
.col-cum { color: var(--accent-green); }
.symbol-block { border: 1px solid var(--border); margin-bottom: 4px; }
.symbol-block.collapsed > .symbol-children { display: none; }
.tree-node.collapsed > .tree-children { display: none; }
code { color: var(--accent-orange); }
a { color: var(--accent-cyan); }

/* ---- Tab 3: disassembly ---- */
/* Use stupidly short class names here because it's a large fraction of the file size! */
.dl { font-family: var(--font-mono); font-size: 11px; }
.dh { display: flex; position: sticky; top: 0; background: var(--bg-panel); color: var(--accent-blue); z-index: 5; }
.dh .s, .dh .d { flex: 1 1 0; padding: 3px 6px; }
.r { display: flex; }
.r:hover { background: var(--bg-hover); }
.r.ss { border-top: 1px solid var(--border-subtle); }
.r .s { flex: 0 0 33.333%; min-height: 1.4em; padding: 1px 6px; color: var(--accent-yellow); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; direction: rtl; text-align: left; }
.r .s.h { color: var(--accent-green); }
.r .d { flex: 1 1 0; min-height: 1.4em; padding: 1px 6px; white-space: pre-wrap; word-break: break-all; color: var(--text); }
"""

JS = r"""
function showTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.tab-page').forEach(p => p.classList.toggle('active', p.id === 'page-' + name));
}
function setExpanded(el, expanded) {
  el.classList.toggle('collapsed', !expanded);
  const arrow = el.querySelector(':scope > .tree-row .tree-arrow');
  if (arrow) arrow.textContent = expanded ? '\u25BC' : '\u25B6';
}
function expandSingleChildChains(container) {
  // The node that was just expanded has this children container. If it
  // contains exactly one node, expand that node too and recurse, so the
  // user doesn't have to click through a trivial single-child wrapper.
  for (;;) {
    const nodes = container.querySelectorAll(':scope > .tree-node');
    if (nodes.length !== 1) break;
    const node = nodes[0];
    const tc = node.querySelector(':scope > .tree-children');
    if (!tc) break;  // leaf: no arrow, nothing to expand
    setExpanded(node, true);
    container = tc;
  }
}
function toggle(el, blockClass, childSel) {
  const block = el.closest('.' + blockClass);
  const collapsed = block.classList.contains('collapsed');
  setExpanded(block, collapsed);
  if (collapsed) {
    const c = block.querySelector(':scope > ' + childSel);
    if (c) expandSingleChildChains(c);
  }
}
function toggleSymbol(el) { toggle(el, 'symbol-block', '.symbol-children'); }
function toggleNode(el) { toggle(el, 'tree-node', '.tree-children'); }
function gotoDisasm(addrHex) {
  showTab('disasm');
  const el = document.getElementById('d-' + addrHex);
  if (el) {
    const scroller = el.closest('.tab-page');
    const offset = el.offsetTop - (scroller ? scroller.offsetTop : 0);
    scroller.scrollTop = Math.max(0, offset - 40);
  }
}
"""

def esc(s):
    return html.escape(str(s))

def disasm_link(scope_path, scope_first_addr):
    """Render the "click" link for a node, or empty if no matching address."""
    target = scope_first_addr.get(scope_path)
    if target is None:
        return ""
    return f'<a href="javascript:void(0)" onclick="event.stopPropagation(); gotoDisasm(\'{target:x}\')">→</a>'

def render_tree_node(node, depth, total_instr_bytes, scope_path, scope_first_addr):
    """Render a single tree node row and its descendants as flex rows.

    Each row has aligned columns: name | disasm | location | self | cum | %.
    The name column embeds a leading toggle arrow if the node has children.
    """
    has_children = bool(node.children)
    name_cls = "tree-name leaf" if not has_children else "tree-name"
    clickable = ' clickable" onclick="toggleNode(this)' if has_children else ''
    loc = f"{node.file}:{node.line}" if node.file else ""
    pct = (node.cum / total_instr_bytes * 100) if total_instr_bytes else 0
    arrow = "\u25B6" if has_children else ""
    out = (
        f'<div class="tree-row{clickable}">'
        f'<span class="col-name" style="--depth:{depth}">'
        f'<span class="{name_cls}"><span class="tree-arrow">{arrow}</span>{esc(node.name) or "(?)"}</span>'
        f'</span>'
        f'<span class="col-loc" title="{esc(loc)}">{esc(loc)}</span>'
        f'<span class="col-disasm">{disasm_link(scope_path, scope_first_addr)}</span>'
        f'<span class="col-self">{node.self_size or "-"}</span>'
        f'<span class="col-cum">{node.cum}</span>'
        f'<span class="col-pct">{pct:.2f}%</span>'
        f'</div>'
    )
    if has_children:
        out += '<div class="tree-children">'
        for child in node.children.values():
            child_scope = f"{scope_path}/{child.name}"
            out += f'<div class="tree-node collapsed">{render_tree_node(child, depth + 1, total_instr_bytes, child_scope, scope_first_addr)}</div>'
        out += "</div>"
    return out

def tree_header():
    return (
        '<div class="tree-header">'
        '<span class="col-name">Function</span>'
        '<span class="col-loc">Location</span>'
        '<span class="col-disasm">Disassembly</span>'
        '<span class="col-self">Self</span>'
        '<span class="col-cum">Cum</span>'
        '<span class="col-pct">Cum%</span>'
        '</div>'
    )

def render_tab1(symbols_with_trees, total_instr_bytes, scope_first_addr):
    blocks = []
    for sym, root in symbols_with_trees:
        pct = root.cum / total_instr_bytes * 100
        loc = f"{root.file}:{root.line}" if root.file else ""
        has_children = bool(root.children)
        clickable = ' clickable" onclick="toggleSymbol(this)' if has_children else ''
        arrow = "\u25B6" if has_children else ""
        sym_scope = sym["name"]
        sym_row = (
            f'<div class="tree-row{clickable}">'
            f'<span class="col-name" style="--depth:0">'
            f'<span class="symbol-name"><span class="tree-arrow">{arrow}</span>{esc(sym["name"])}</span>'
            f'</span>'
            f'<span class="col-loc" title="{esc(loc)}">{esc(loc)}</span>'
            f'<span class="col-disasm">{disasm_link(sym_scope, scope_first_addr)}</span>'
            f'<span class="col-self">{root.self_size or "-"}</span>'
            f'<span class="col-cum">{root.cum}</span>'
            f'<span class="col-pct">{pct:.2f}%</span>'
            f'</div>'
        )
        children_html = ""
        for child in root.children.values():
            child_scope = f"{sym_scope}/{child.name}"
            children_html += f'<div class="tree-node collapsed">{render_tree_node(child, 1, total_instr_bytes, child_scope, scope_first_addr)}</div>'
        # .symbol-block starts collapsed; toggling it hides .symbol-children.
        blocks.append(
            f'<div class="symbol-block collapsed">'
            f'{tree_header()}'
            f'{sym_row}'
            f'<div class="symbol-children">{children_html}</div>'
            f'</div>'
        )
    body = "\n".join(blocks)
    return f"""
    <div class="summary">Total: <b>{total_instr_bytes}</b> bytes across <b>{len(symbols_with_trees)}</b> function symbols. Click a symbol to expand its inline call tree.</div>
    {body}
    """

def render_tab2(func_entries, total_instr_bytes):
    rows = []
    for name, file, line, size, count in func_entries:
        pct = size / total_instr_bytes * 100
        loc = f"{file}:{line}" if file else ""
        rows.append(
            f'<tr>'
            f'<td data-v="{size}" class="num">{size}</td>'
            f'<td data-v="{pct}" class="num">{pct:.2f}%</td>'
            f'<td data-v="{count}" class="num">{count}</td>'
            f'<td>{esc(name) or "(?)"}</td>'
            f'<td>{esc(loc)}</td>'
            f'</tr>'
        )
    body = "\n".join(rows)
    return f"""
    <div class="summary">Total: <b>{total_instr_bytes}</b> bytes. Each instruction is attributed to its innermost enclosing scope. Contributions are summed across all inlined instances of a function.</div>
    <table class="sortable">
      <thead>
        <tr>
          <th class="num">Size (B)</th>
          <th class="num">%</th>
          <th class="num">Instrs</th>
          <th>Function</th>
          <th>Location</th>
        </tr>
      </thead>
      <tbody>{body}</tbody>
    </table>
    """

def render_tab3(disasm, stacks):
    """Render the full objdump disassembly with an inline-scope column."""
    rows = []
    last_scope = None
    seen_single = set()
    for line in disasm.splitlines():
        scope = ""
        head = False
        m = _ADDR_LINE_RE.match(line)
        if m:
            addr = int(m.group(1), 16)
            stack = stacks.get(addr)
            if stack:
                path = "/".join(name for name, _, _ in reversed(stack))
                if path != last_scope:
                    scope = path
                    if "/" not in path and path not in seen_single:
                        seen_single.add(path)
                        head = True
                last_scope = path
            else:
                last_scope = None
        cls = "r" + (" ss" if scope else "")
        scope_cls = "s" + (" h" if head else "")
        row_id = f' id="d-{m.group(1)}"' if m else ""
        rows.append(
            f'<div class="{cls}"{row_id}>'
            f'<span class="{scope_cls}">{esc(scope)}</span>'
            f'<span class="d">{esc(line)}</span>'
            f'</div>'
        )
    body = "\n".join(rows)
    return f"""
    <div class="summary">The left column shows the inline call stack (outermost/innermost). It's blank if there's no change from the previous instruction.</div>
    <div class="dl">
      <div class="dh">
        <span class="s">Inline scope</span>
        <span class="d">Disassembly</span>
      </div>
      {body}
    </div>
    """

def render_html(tab1_html, tab2_html, tab3_html, elf_name, total_instr_bytes):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(elf_name)} &middot; codesizer</title>
<style>{CSS}</style>
<script>{JS}</script>
</head>
<body>
<header>
  <h1>{esc(elf_name)} &middot; {total_instr_bytes} bytes</h1>
</header>
<div class="tabs">
  <div class="tab active" data-tab="symbols" onclick="showTab('symbols')">Symbols (inline tree)</div>
  <div class="tab" data-tab="flat" onclick="showTab('flat')">Functions (flattened)</div>
  <div class="tab" data-tab="disasm" onclick="showTab('disasm')">Disassembly</div>
</div>
<div id="content">
<div id="page-symbols" class="tab-page active">{tab1_html}</div>
<div id="page-flat" class="tab-page">{tab2_html}</div>
<div id="page-disasm" class="tab-page">{tab3_html}</div>
</div>
</body>
</html>
"""

# -----------------------------------------------------------------------------
# Main

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("elf", help="input ELF file")
    p.add_argument("output", help="output HTML file")
    p.add_argument("--cross-prefix", default="riscv32-unknown-elf-",
        help="prefix for objdump and addr2line (default: riscv32-unknown-elf-)")
    p.add_argument("--section", "-j", action="append",
        help="Specify ELF section. Pass multiple times for multiple sections. If unspecified, .text is used.")
    args = p.parse_args(argv)

    if not os.path.isfile(args.elf):
        p.error(f"ELF file not found: {args.elf}")

    prefix = args.cross_prefix
    sections = [".text"] if args.section is None else args.section

    print(f"Disassembling {', '.join(sections)} from {args.elf}...")
    disasm = objdump_disasm(prefix, args.elf, sections)
    instrs = parse_instructions(disasm)
    if len(instrs) == 0: sys.exit("Disassembly returned no instructions!")
    instr_by_addr = {a: s for a, s in instrs}
    addresses = [a for a, _ in instrs]
    total_instr_bytes = sum(s for _, s in instrs)
    print(f"  {len(instrs)} instructions, {total_instr_bytes} bytes")

    print(f"Reading symbol table...")
    symtab = objdump_symbols(prefix, args.elf, sections)
    symbols = parse_symbols(symtab)
    print(f"  {len(symbols)} function symbols")

    print(f"Resolving inline stacks for {len(addresses)} addresses...")
    stacks = addr2line_batch(prefix, args.elf, addresses)
    strip_common_path_prefix(stacks)
    print(f"  resolved {len(stacks)} addresses")

    # Heuristic for zero-sized symbols (e.g. from asm sources): just set the
    # size to the offset til the next symbol, *unless* fully contained within
    # an earlier symbol of known size. (Limitation: doesn't work for the
    # final symbol, but that's often an end-of-image symbol from the linker
    # script.)
    skip_until = -1
    for s, t in itertools.pairwise(symbols):
        should_skip = s["addr"] < skip_until
        skip_until = max(skip_until, s["size"] + s["addr"])
        if should_skip: continue
        if s["size"] != 0: continue
        assert s["addr"] <= t["addr"]
        s["size"] = t["addr"] - s["addr"]

    # Drop anything which still had zero size under that heuristic:
    symbols = list(s for s in symbols if s["size"] != 0)

    # for s in symbols: print(f'{s["addr"]:04x} -> {s["addr"] + s["size"]:04x}: {s["name"]}')

    # For tab 1: per-symbol inline trees.
    # Bucket each address (that has a stack) to its containing symbol once,
    # via bisect on the sorted symbol start addresses. This avoids the O(syms *
    # addrs) scan that would otherwise happen inside build_symbol_tree.
    print("Sorting...")
    sym_starts = [s["addr"] for s in symbols]
    addrs_by_sym = [[] for _ in symbols]
    stack_addrs_sorted = sorted(a for a in stacks if a in instr_by_addr)
    for a in stack_addrs_sorted:
        idx = bisect.bisect_right(sym_starts, a) - 1
        if idx < 0:
            continue
        if a >= symbols[idx]["addr"] + symbols[idx]["size"]:
            continue
        addrs_by_sym[idx].append(a)
    symbols_with_trees = []
    for idx, sym in enumerate(symbols):
        root = build_symbol_tree(sym, addrs_by_sym[idx], stacks, instr_by_addr)
        if root.cum == 0:
            continue
        sort_children(root)
        symbols_with_trees.append((sym, root))
    symbols_with_trees.sort(key=lambda sr: sr[1].cum, reverse=True)

    # For tab 2: flat ranking by innermost function.
    # Group by (name, file): different source lines within the same function
    # are collapsed, but the same name in different translation units (files)
    # stays separate.
    flat = {}
    for addr in addresses:
        size = instr_by_addr[addr]
        stack = stacks.get(addr)
        if stack:
            name, file, line = stack[0]
        else:
            name, file, line = "(unknown)", "", ""
        key = (name, file)
        e = flat.get(key)
        if e is None:
            flat[key] = [size, 1, line]
        else:
            e[0] += size
            e[1] += 1
    func_entries = sorted(
        ((name, file, v[2], v[0], v[1]) for (name, file), v in flat.items()),
        key=lambda x: x[3],
        reverse=True,
    )

    # Statically resolve, for each inline scope path, the first instruction
    # address whose inline stack has that scope as a prefix. Used by tab
    # 1's "Disassembly" links, which scroll to a specific point on tab 3.
    scope_first_addr = {}
    for addr, _ in instrs:
        stack = stacks.get(addr)
        if not stack:
            continue
        path = ""
        for i, (name, _, _) in enumerate(reversed(stack)):
            path = name if i == 0 else path + "/" + name
            if path not in scope_first_addr:
                scope_first_addr[path] = addr

    print("Rendering HTML...")
    tab1 = render_tab1(symbols_with_trees, total_instr_bytes, scope_first_addr)
    tab2 = render_tab2(func_entries, total_instr_bytes)
    tab3 = render_tab3(disasm, stacks)
    html_doc = render_html(tab1, tab2, tab3, os.path.basename(args.elf), total_instr_bytes)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(html_doc)
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()

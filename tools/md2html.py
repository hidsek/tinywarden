#!/usr/bin/env python3
"""Builds the board's manual page (GET /manual, only with the status page unlocked) from docs/, at build time.

    md2html.py OUT.html.gz docs/MANUAL.md docs/SETUP.md docs/MANUAL.en.md docs/SETUP.en.md

One gzipped HTML page holding every document given, each under its own anchor, so the board serves exactly
the manual of the firmware it runs. Only the Markdown these documents use is handled: headings, paragraphs,
lists (nested by indentation), tables, fenced code, block quotes, `code`, **bold** and [links](...).
Links between the documents become in-page anchors; links to other files in docs/ go to GitHub.
No third-party modules, so the ESP-IDF Python runs it as is.
"""
import gzip
import html
import os
import re
import sys

REPO = "https://github.com/hidsek/tinywarden/blob/main/docs/"
ANCHORS = {"MANUAL.md": "ja", "SETUP.md": "ja-setup", "MANUAL.en.md": "en", "SETUP.en.md": "en-setup"}
NAV = [("ja", "使い方"), ("ja-setup", "機器ごとの設定"), ("en", "Manual (English)"), ("en-setup", "Setup (English)")]
LIST_RE = re.compile(r"^(\s*)([-*]|\d+\.)\s+(.*)$")


def link_target(url):
    if re.match(r"^[a-z]+:", url) or url.startswith("#"):
        return url
    name, _, frag = url.partition("#")
    base = os.path.basename(name)
    if base in ANCHORS:
        return "#" + ANCHORS[base]
    return REPO + base + ("#" + frag if frag else "")


def inline(text):
    out, pos = [], 0
    # Code spans first, so nothing inside them is touched
    for m in re.finditer(r"`([^`]+)`", text):
        out.append(inline_plain(text[pos:m.start()]))
        out.append("<code>" + html.escape(m.group(1)) + "</code>")
        pos = m.end()
    out.append(inline_plain(text[pos:]))
    return "".join(out)


def inline_plain(text):
    s = html.escape(text, quote=False)
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)",
               lambda m: '<a href="%s">%s</a>' % (html.escape(link_target(html.unescape(m.group(2)))), m.group(1)), s)
    return s


def cells(line):
    return [c.strip() for c in line.strip().strip("|").split("|")]


def convert(md, prefix):
    lines = md.split("\n")
    out, para, i, nh = [], [], 0, 0
    lists = []  # stack of (indent, tag)

    def flush_para():
        if para:
            out.append("<p>" + inline(" ".join(para)) + "</p>")
            para.clear()

    def close_lists(to_indent=-1):
        while lists and lists[-1][0] > to_indent:
            out.append("</li></%s>" % lists.pop()[1])

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        ind = len(line) - len(line.lstrip())
        if stripped.startswith("```"):
            flush_para()
            if not (lists and ind > lists[-1][0]):  # an indented fence belongs to the list item above
                close_lists()
            j = i + 1
            while j < len(lines) and not lines[j].strip().startswith("```"):
                j += 1
            code = "\n".join(l[ind:] if l[:ind].strip() == "" else l for l in lines[i + 1:j])
            out.append("<pre><code>" + html.escape(code) + "</code></pre>")
            i = j + 1
            continue
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if m:
            flush_para()
            close_lists()
            level = len(m.group(1))
            nh += 1
            hid = prefix if nh == 1 else "%s-%d" % (prefix, nh)
            out.append('<h%d id="%s">%s</h%d>' % (level, hid, inline(m.group(2)), level))
            i += 1
            continue
        if stripped.startswith("|") and i + 1 < len(lines) and re.match(r"^\s*\|[\s:|-]+\|\s*$", lines[i + 1]):
            flush_para()
            close_lists()
            head = cells(line)
            rows = []
            i += 2
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append(cells(lines[i]))
                i += 1
            t = ["<div class=t><table><tr>" + "".join("<th>%s</th>" % inline(c) for c in head) + "</tr>"]
            for r in rows:
                t.append("<tr>" + "".join("<td>%s</td>" % inline(c) for c in r) + "</tr>")
            out.append("".join(t) + "</table></div>")
            continue
        if stripped.startswith(">"):
            flush_para()
            close_lists()
            q = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                q.append(lines[i].strip()[1:].strip())
                i += 1
            out.append("<blockquote>" + inline(" ".join(q)) + "</blockquote>")
            continue
        m = LIST_RE.match(line)
        if m:
            flush_para()
            li = len(m.group(1))
            tag = "ol" if m.group(2)[0].isdigit() else "ul"
            if lists and li < lists[-1][0]:
                close_lists(li)
            if lists and lists[-1][0] == li and lists[-1][1] != tag:
                close_lists(li - 1)
            if not lists or li > lists[-1][0]:
                out.append("<%s>" % tag)
                lists.append((li, tag))
                out.append("<li>" + inline(m.group(3)))
            else:
                out.append("</li><li>" + inline(m.group(3)))
            i += 1
            continue
        if not stripped:
            flush_para()
            # A blank line ends a list unless an indented line or another item follows
            nxt = lines[i + 1] if i + 1 < len(lines) else ""
            if lists and not (nxt.startswith(" ") and nxt.strip()) and not LIST_RE.match(nxt):
                close_lists()
            i += 1
            continue
        if lists and line.startswith(" "):
            # More of the current list item; after a blank line, a paragraph of its own
            if lines[i - 1].strip():
                out.append(" " + inline(stripped))
            else:
                out.append("<p>" + inline(stripped) + "</p>")
            i += 1
            continue
        close_lists()
        para.append(stripped)
        i += 1
    flush_para()
    close_lists()
    return "\n".join(out)


STYLE = """
:root{--bg:#fff;--fg:#1a1a1a;--mute:#666;--line:#ddd;--code:#f4f4f4;--link:#0b57d0}
@media(prefers-color-scheme:dark){:root{--bg:#161616;--fg:#eee;--mute:#999;--line:#333;--code:#242424;--link:#8ab4f8}}
body{background:var(--bg);color:var(--fg);font:15px/1.7 -apple-system,'Hiragino Sans','Hiragino Kaku Gothic ProN',
'Noto Sans JP',sans-serif;max-width:760px;margin:0 auto;padding:16px}
a{color:var(--link)}h1{font-size:22px;margin-top:40px;border-top:2px solid var(--line);padding-top:24px}
h1:first-of-type{border:0;margin-top:8px}h2{font-size:18px;margin-top:28px}h3{font-size:16px}
nav{position:sticky;top:0;background:var(--bg);padding:8px 0;border-bottom:1px solid var(--line);font-size:14px}
nav a{margin-right:12px;white-space:nowrap}
code{font:13px ui-monospace,Menlo,monospace;background:var(--code);padding:1px 4px;border-radius:4px;word-break:break-all}
pre{background:var(--code);padding:10px;border-radius:6px;overflow-x:auto}pre code{padding:0;word-break:normal}
.t{overflow-x:auto}table{border-collapse:collapse;margin:8px 0}td,th{border:1px solid var(--line);padding:4px 8px;
text-align:left;vertical-align:top}th{background:var(--code)}blockquote{margin:8px 0;padding:4px 12px;
border-left:3px solid var(--line);color:var(--mute)}.mute{color:var(--mute);font-size:13px}
"""


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    out_path, docs = sys.argv[1], sys.argv[2:]
    parts = []
    for path in docs:
        base = os.path.basename(path)
        prefix = ANCHORS.get(base, re.sub(r"[^a-z0-9]+", "-", base.lower()))
        with open(path, encoding="utf-8") as f:
            parts.append('<section lang="%s">' % ("en" if ".en." in base else "ja") + convert(f.read(), prefix) + "</section>")
    nav = "<nav>" + "".join('<a href="#%s">%s</a>' % (a, t) for a, t in NAV) + '<a href="/">管理ページ</a></nav>'
    page = ("<!doctype html><html lang=ja><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'><title>tinywarden マニュアル</title>"
            "<style>" + STYLE.replace("\n", "") + "</style>" + nav + "".join(parts) +
            "<p class=mute>この機器のファームウェアに入っている版です。最新は " + html.escape(REPO) + "</p></html>")
    data = gzip.compress(page.encode("utf-8"), compresslevel=9, mtime=0)
    with open(out_path, "wb") as f:
        f.write(data)
    print(f"md2html: {len(page.encode())} bytes -> {len(data)} gzipped")


if __name__ == "__main__":
    main()

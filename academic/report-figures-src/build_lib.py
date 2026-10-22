"""Low-level helpers for expanding the Ninsho blackbook at the WordprocessingML level.

Every element produced here reuses the formatting of the existing report:
Normal body text (justified, 6 pt after), Heading 1-3 with the chapter list
(numId 2), ListParagraph bullets (numId 3) and fresh numbered-list instances
(abstract list 1), the report's table format (8,666-twip width, #E8E7F3 header
row, 10 pt bold header, 9 pt cells), and the TableCaption / FigureCaption
styles that feed the List of Tables and List of Figures.
"""
import copy
import re
import shutil
from pathlib import Path

from lxml import etree

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
WP = "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
A = "http://schemas.openxmlformats.org/drawingml/2006/main"
PIC = "http://schemas.openxmlformats.org/drawingml/2006/picture"
NS = {"w": W, "r": R, "wp": WP, "a": A, "pic": PIC}
XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"
TABLE_WIDTH = 8666
HEADER_FILL = "E8E7F3"


def w(tag):
    return f"{{{W}}}{tag}"


def el(tag, attrs=None, children=()):
    e = etree.Element(w(tag))
    for k, v in (attrs or {}).items():
        e.set(w(k) if ":" not in k and not k.startswith("{") else k, v)
    for c in children:
        e.append(c)
    return e


INLINE = re.compile(r"(\*\*[^*]+\*\*|`[^`]+`|\*[^*]+\*)")


def runs(text, size=None, bold=False, italic=False, mono_size=None):
    """Inline markup: **bold**, *italic*, `code`."""
    out = []
    for part in INLINE.split(text):
        if not part:
            continue
        b, i, mono, t = bold, italic, False, part
        if part.startswith("**") and part.endswith("**"):
            b, t = True, part[2:-2]
        elif part.startswith("`") and part.endswith("`"):
            mono, t = True, part[1:-1]
        elif part.startswith("*") and part.endswith("*") and len(part) > 2:
            i, t = True, part[1:-1]
        rpr = el("rPr")
        if mono:
            rpr.append(el("rFonts", {"ascii": "Courier New", "hAnsi": "Courier New", "cs": "Courier New"}))
        if b:
            rpr.append(el("b")); rpr.append(el("bCs"))
        if i:
            rpr.append(el("i")); rpr.append(el("iCs"))
        sz = mono_size if (mono and mono_size) else (size if size else (22 if mono else None))
        if sz:
            rpr.append(el("sz", {"val": str(sz)})); rpr.append(el("szCs", {"val": str(sz)}))
        r = el("r")
        if len(rpr):
            r.append(rpr)
        tt = el("t"); tt.text = t; tt.set(XML_SPACE, "preserve")
        r.append(tt)
        out.append(r)
    return out


class Builder:
    def __init__(self, unpacked: Path):
        self.root_dir = unpacked
        self.doc_path = unpacked / "word" / "document.xml"
        self.tree = etree.parse(str(self.doc_path))
        self.body = self.tree.getroot().find("w:body", NS)
        self.rels_path = unpacked / "word" / "_rels" / "document.xml.rels"
        self.rels = etree.parse(str(self.rels_path))
        self.num_path = unpacked / "word" / "numbering.xml"
        self.numbering = etree.parse(str(self.num_path))
        ids = [int(x) for x in re.findall(r'id="(\d+)"', etree.tostring(self.tree).decode())]
        self.next_docpr = max(ids + [100]) + 1000
        self.next_rid = max(int(i[3:]) for i in self.rels.getroot().xpath("@Id|*/@Id")) + 1
        self.next_num = max(int(n.get(w("numId"))) for n in self.numbering.getroot().findall("w:num", NS)) + 1

    # ── lookup ──────────────────────────────────────────────────────────────
    @staticmethod
    def text(e):
        return "".join(t.text or "" for t in e.iter(w("t")))

    def find_p(self, needle, style=None, nth=0):
        hits = []
        for p in self.body.iter(w("p")):
            st = p.find("w:pPr/w:pStyle", NS)
            if style is not None and (st is None or st.get(w("val")) != style):
                continue
            if needle in self.text(p):
                hits.append(p)
        if not hits:
            raise KeyError(f"anchor not found: {needle!r}")
        if nth == 0 and len(hits) > 1 and style is None:
            # Prefer a body-level paragraph, never one inside the TOC.
            hits = [h for h in hits if (h.find("w:pPr/w:pStyle", NS) is None or
                                        not h.find("w:pPr/w:pStyle", NS).get(w("val")).startswith("TOC"))]
        return hits[nth]

    def table_after(self, caption_needle):
        cap = self.find_p(caption_needle, style="TableCaption")
        nxt = cap.getnext()
        while nxt is not None and nxt.tag != w("tbl"):
            nxt = nxt.getnext()
        return nxt

    @staticmethod
    def insert_after(anchor, elements):
        cur = anchor
        for e in elements:
            cur.addnext(e)
            cur = e
        return cur

    # ── paragraphs ──────────────────────────────────────────────────────────
    def para(self, text, align="both", after=120, keep_next=False, style=None, size=None, page_break=False):
        ppr = el("pPr")
        if style:
            ppr.append(el("pStyle", {"val": style}))
        if keep_next:
            ppr.append(el("keepNext"))
        if page_break:
            ppr.append(el("pageBreakBefore"))
        ppr.append(el("spacing", {"after": str(after)}))
        ppr.append(el("jc", {"val": align}))
        p = el("p", children=[ppr])
        for r in runs(text, size=size):
            p.append(r)
        return p

    def heading(self, level, text, numbered=True):
        ppr = el("pPr", children=[el("pStyle", {"val": f"Heading{level}"})])
        numpr = el("numPr")
        if numbered:
            numpr.append(el("ilvl", {"val": str(level - 1)}))
            numpr.append(el("numId", {"val": "2"}))
        else:
            numpr.append(el("ilvl", {"val": "0"}))
            numpr.append(el("numId", {"val": "0"}))
        ppr.append(numpr)
        p = el("p", children=[ppr])
        r = el("r"); t = el("t"); t.text = text; r.append(t); p.append(r)
        return p

    def appendix_title(self, text):
        ppr = el("pPr", children=[el("pStyle", {"val": "FrontMatterTitleinTOC"})])
        if text.startswith("Appendix A:"):
            ppr.append(el("pageBreakBefore"))
        p = el("p", children=[ppr])
        r = el("r"); t = el("t"); t.text = text; r.append(t); p.append(r)
        return p

    def new_list(self):
        num = el("num", {"numId": str(self.next_num)})
        num.append(el("abstractNumId", {"val": "1"}))
        lo = el("lvlOverride", {"ilvl": "0"}); lo.append(el("startOverride", {"val": "1"})); num.append(lo)
        self.numbering.getroot().append(num)
        self.next_num += 1
        return self.next_num - 1

    def list_item(self, text, num_id):
        ppr = el("pPr", children=[el("pStyle", {"val": "ListParagraph"}),
                                  el("numPr", children=[el("ilvl", {"val": "0"}), el("numId", {"val": str(num_id)})]),
                                  el("spacing", {"after": "80"}), el("jc", {"val": "both"})])
        p = el("p", children=[ppr])
        for r in runs(text):
            p.append(r)
        return p

    def bullets(self, items):
        return [self.list_item(t, 3) for t in items]

    def numbered(self, items):
        nid = self.new_list()
        return [self.list_item(t, nid) for t in items]

    def code(self, lines):
        out = []
        for i, line in enumerate(lines):
            ppr = el("pPr", children=[
                el("keepNext") if i < len(lines) - 1 else el("keepLines"),
                el("shd", {"val": "clear", "color": "auto", "fill": "F2F2F2"}),
                el("spacing", {"before": "0", "after": "0", "line": "240", "lineRule": "auto"}),
                el("ind", {"left": "284", "right": "284"}),
            ])
            if i == len(lines) - 1:
                ppr.find("w:spacing", NS).set(w("after"), "160")
            p = el("p", children=[ppr])
            r = el("r", children=[el("rPr", children=[
                el("rFonts", {"ascii": "Courier New", "hAnsi": "Courier New", "cs": "Courier New"}),
                el("sz", {"val": "17"}), el("szCs", {"val": "17"})])])
            t = el("t"); t.text = line if line else " "; t.set(XML_SPACE, "preserve"); r.append(t)
            p.append(r)
            out.append(p)
        return out

    # ── captions ────────────────────────────────────────────────────────────
    def caption(self, kind, key, text):
        style = "TableCaption" if kind == "T" else "FigureCaption"
        ppr = el("pPr", children=[el("pStyle", {"val": style})])
        if kind == "T":
            ppr.append(el("keepNext"))
        p = el("p", children=[ppr])
        r1 = el("r", children=[el("rPr", children=[el("b"), el("bCs")])])
        t1 = el("t"); t1.text = f"{{{kind}LABEL:{key}}}: "; t1.set(XML_SPACE, "preserve"); r1.append(t1)
        r2 = el("r"); t2 = el("t"); t2.text = text; r2.append(t2)
        p.append(r1); p.append(r2)
        return p

    # ── tables ──────────────────────────────────────────────────────────────
    def _cell(self, text, width, header=False, align=None):
        borders = el("tcBorders", children=[el(s, {"val": "single", "sz": "4", "space": "0", "color": "000000"})
                                            for s in ("top", "left", "bottom", "right")])
        tcpr = el("tcPr", children=[el("tcW", {"w": str(width), "type": "dxa"}), borders])
        if header:
            tcpr.append(el("shd", {"val": "clear", "color": "auto", "fill": HEADER_FILL}))
        tcpr.append(el("tcMar", children=[el("top", {"w": "60", "type": "dxa"}), el("left", {"w": "100", "type": "dxa"}),
                                          el("bottom", {"w": "60", "type": "dxa"}), el("right", {"w": "100", "type": "dxa"})]))
        tcpr.append(el("vAlign", {"val": "center"}))
        tc = el("tc", children=[tcpr])
        for k, line in enumerate(str(text).split("\n")):
            ppr = el("pPr", children=[el("spacing", {"after": "0", "line": "240", "lineRule": "auto"})])
            if header or align:
                ppr.append(el("jc", {"val": align or "center"}))
            p = el("p", children=[ppr])
            for r in runs(line, size=20 if header else 18, bold=header, mono_size=17):
                p.append(r)
            tc.append(p)
        return tc

    def table(self, headers, rows, widths):
        total = sum(widths)
        cols = [round(TABLE_WIDTH * x / total) for x in widths]
        cols[-1] = TABLE_WIDTH - sum(cols[:-1])
        tblpr = el("tblPr", children=[
            el("tblW", {"w": str(TABLE_WIDTH), "type": "dxa"}), el("jc", {"val": "center"}),
            el("tblBorders", children=[el(s, {"val": "single", "sz": "4", "space": "0", "color": "auto"})
                                       for s in ("top", "left", "bottom", "right", "insideH", "insideV")]),
            el("tblLayout", {"type": "fixed"}),
            el("tblCellMar", children=[el("left", {"w": "10", "type": "dxa"}), el("right", {"w": "10", "type": "dxa"})]),
            el("tblLook", {"val": "0000", "firstRow": "0", "lastRow": "0", "firstColumn": "0", "lastColumn": "0",
                           "noHBand": "0", "noVBand": "0"})])
        grid = el("tblGrid", children=[el("gridCol", {"w": str(c)}) for c in cols])
        tbl = el("tbl", children=[tblpr, grid])
        hdr = el("tr", children=[el("trPr", children=[el("tblHeader"), el("cantSplit"), el("jc", {"val": "center"})])])
        for h, c in zip(headers, cols):
            hdr.append(self._cell(h, c, header=True))
        tbl.append(hdr)
        for row in rows:
            tr = el("tr", children=[el("trPr", children=[el("cantSplit"), el("jc", {"val": "center"})])])
            for v, c in zip(row, cols):
                tr.append(self._cell(v, c))
            tbl.append(tr)
        return tbl

    # ── images ──────────────────────────────────────────────────────────────
    def image(self, path: Path, width_cm):
        from PIL import Image
        media = self.root_dir / "word" / "media"
        name = f"exp_{path.stem}.png"
        shutil.copy(path, media / name)
        rid = f"rId{self.next_rid}"; self.next_rid += 1
        rel = etree.SubElement(self.rels.getroot(), "{http://schemas.openxmlformats.org/package/2006/relationships}Relationship")
        rel.set("Id", rid)
        rel.set("Type", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image")
        rel.set("Target", f"media/{name}")
        with Image.open(path) as im:
            wpx, hpx = im.size
        cx = int(width_cm * 360000)
        cy = int(cx * hpx / wpx)
        max_cy = int(19.0 * 360000)
        if cy > max_cy:
            cy = max_cy; cx = int(cy * wpx / hpx)
        did = self.next_docpr; self.next_docpr += 1
        xml = f'''<w:p xmlns:w="{W}" xmlns:wp="{WP}" xmlns:a="{A}" xmlns:pic="{PIC}" xmlns:r="{R}">
<w:pPr><w:keepNext/><w:spacing w:before="120" w:after="0" w:line="240" w:lineRule="auto"/><w:jc w:val="center"/></w:pPr>
<w:r><w:rPr><w:noProof/></w:rPr><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0">
<wp:extent cx="{cx}" cy="{cy}"/><wp:effectExtent l="0" t="0" r="0" b="0"/>
<wp:docPr id="{did}" name="{name}" descr="{path.stem}"/>
<wp:cNvGraphicFramePr><a:graphicFrameLocks noChangeAspect="1"/></wp:cNvGraphicFramePr>
<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">
<pic:pic><pic:nvPicPr><pic:cNvPr id="{did}" name="{name}"/><pic:cNvPicPr><a:picLocks noChangeAspect="1"/></pic:cNvPicPr></pic:nvPicPr>
<pic:blipFill><a:blip r:embed="{rid}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>
<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>
</pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>'''
        return etree.fromstring(xml)

    # ── block renderer ──────────────────────────────────────────────────────
    def render(self, blocks, assets: Path):
        out = []
        for b in blocks:
            k = b[0]
            if k == "h2":
                out.append(self.heading(2, b[1]))
            elif k == "h3":
                out.append(self.heading(3, b[1]))
            elif k == "h2u":
                out.append(self.heading(2, b[1], numbered=False))
            elif k == "h3u":
                out.append(self.heading(3, b[1], numbered=False))
            elif k == "app":
                out.append(self.appendix_title(b[1]))
            elif k == "p":
                out.append(self.para(b[1]))
            elif k == "b":
                out.extend(self.bullets(b[1]))
            elif k == "n":
                out.extend(self.numbered(b[1]))
            elif k == "code":
                out.extend(self.code(b[1]))
            elif k == "tbl":
                _, key, cap, headers, rows, widths = b
                out.append(self.caption("T", key, cap))
                out.append(self.table(headers, rows, widths))
                spacer = self.para("", after=0, size=8)
                spacer.find("w:pPr/w:spacing", NS).set(w("line"), "240")
                out.append(spacer)
            elif k == "fig":
                _, key, cap, path, width = b
                out.append(self.image(assets / path if not Path(path).is_absolute() else Path(path), width))
                out.append(self.caption("F", key, cap))
            else:
                raise ValueError(k)
        return out

    # ── save ────────────────────────────────────────────────────────────────
    def save(self):
        self.tree.write(str(self.doc_path), xml_declaration=True, encoding="UTF-8", standalone=True)
        self.rels.write(str(self.rels_path), xml_declaration=True, encoding="UTF-8", standalone=True)
        self.numbering.write(str(self.num_path), xml_declaration=True, encoding="UTF-8", standalone=True)

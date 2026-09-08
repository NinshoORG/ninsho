# The Ninsho site

The product site — what Ninsho is, what it stops, what it costs, and how to run
the demonstration.

## Run it

There is no build step. Open `index.html`, or serve the folder:

```bash
npx serve website
# or
python -m http.server 8080 --directory website
```

## Deploy it

Point any static host at this directory. No configuration, no environment
variables, no server.

| Host | Setting |
| --- | --- |
| Netlify · Vercel · Cloudflare Pages | publish directory `website`, build command *(none)* |
| GitHub Pages | serve from `/website` on `main`, or copy the folder to a `gh-pages` branch |
| Any web server | copy the folder to the document root |

`404.html` is picked up automatically by Netlify, Cloudflare Pages and GitHub
Pages. Its links are root-relative, so it works from any path.

Before a real domain goes live, change the two absolute URLs that assume one:
the `Sitemap:` line in `robots.txt` and the `<loc>` entries in `sitemap.xml`.
They currently read `ninsho.dev`, which is a placeholder rather than a
registration.

## Why there is no framework here

Three of the four packages this site advertises ship with **zero runtime
dependencies**, and CI fails the build if that stops being true. A marketing
site that needed a toolchain, a lockfile and a node_modules tree to render one
page would be arguing against the thing it is selling.

So: three pages, one stylesheet, one 90-line script. The script does two things
— remembers a theme choice and marks the current page in the nav — and degrades
to a perfectly readable site if it never runs at all.

## Structure

```
index.html         the launch page
performance.html   measured numbers, with the hardware stated
demo.html          the ten-panel playground tour
404.html
assets/
  style.css        every token and component
  app.js           theme toggle, current-page marking, copy buttons
  favicon.svg
robots.txt
sitemap.xml
```

## The brand assets

`assets/brand/` holds the identity. The PNGs are the masters — the icon at
1254&nbsp;px and the two horizontal lockups with the tagline. The SVGs are
vector recreations of the same geometry, for the places a megabyte of raster
has no business being: a favicon, a 28&nbsp;px nav mark, a social card.

Every colour in `style.css` was **sampled from the artwork** rather than matched
by eye — `#041526` for the ground, `#0071F0` to `#11D8FE` for the band — so the
site and the logo are the same blue rather than two blues that nearly agree. If
the artwork is ever revised, resample rather than adjust.

[`brand.html`](./brand.html) documents the lockups, the scale test and the four
usage rules.

## The one house rule

**Every claim on this site names the test that demonstrates it.** That is the
`.cite` element — the monospace line with a green check that follows a claim —
and it is a layout primitive rather than a footnote style, because it appears
throughout rather than being collected into one band at the bottom.

If you add a claim and cannot attach a citation to it, the claim does not go on
the site. That is the same rule the library runs on, stated in
[`CONTRIBUTING.md`](../CONTRIBUTING.md), applied to its marketing.

## Keeping the numbers honest

Figures on `performance.html` are measured, not estimated, and every one of them
is reproducible:

```bash
npm run bench --workspace @ninshorg/server
npm run bench --workspace @ninshorg/webauthn
```

They were taken on an **Intel i7-8665U, Node v24.11.1**, which the page states
because the headline ratio moves by a factor of three between machines. If you
update a number, update the hardware line with it — a figure without its
conditions is the failure this project exists around.

The bar chart widths are percentages of the largest value in the set
(143,661 ops/sec). If you change the data, recompute them; a chart whose bars do
not share one scale is worse than no chart.

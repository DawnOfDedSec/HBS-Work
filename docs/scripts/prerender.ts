// Static generation for every route: each page is rendered to real HTML so
// direct refreshes, crawlers and no-JS visitors get content on first response.
// Runs after `vite build`; no extra dependencies (vite + react-dom only).
import { createServer } from "vite";
import { renderToString } from "react-dom/server";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import React from "react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import type { DocSection } from "../src/docs/content";

const e = React.createElement;

const CANON = "https://hbs-tool.docs.potenfyr.in";

interface Page {
  path: string;
  file: string;
  title: string;
  description: string;
}

const vite = await createServer({
  server: { middlewareMode: true },
  appType: "custom",
  logLevel: "error",
});

// doc sections are resolved from content data, so new sections are emitted
// automatically on the next build.
const content = (await vite.ssrLoadModule("/src/docs/content")) as {
  DOC_SECTIONS: DocSection[];
};
const DOC_SECTIONS = content.DOC_SECTIONS;

const pages: Page[] = [
  {
    path: "/",
    file: "index.html",
    title: "HBS Tool: Offline-first host baseline security reviews",
    description:
      "An offline-first, strictly read-only configuration-security review platform: 368 hardening testcases across Linux and Windows, sealed .hbs reports that only the issuing dashboard can decrypt.",
  },
  {
    path: "/docs",
    file: "docs/index.html",
    title: "Getting started | HBS Tool docs",
    description:
      "Install the HBS dashboard, issue a patched extractor, run the strictly read-only scan, and deliver the sealed .hbs report.",
  },
  {
    path: "/examples",
    file: "examples/index.html",
    title: "Examples | HBS Tool",
    description:
      "Real workflows for HBS: offline scans, air-gapped push, filtered re-scans, Windows CI runs, API-driven issuance and batch uploads.",
  },
  {
    path: "/about",
    file: "about/index.html",
    title: "About | HBS Tool",
    description:
      "HBS is an offline-first, strictly read-only host baseline security review platform by PotenFYR Studios: sealed reports, 368 testcases, executive-to-evidence consoles.",
  },
  {
    path: "/license",
    file: "license/index.html",
    title: "License | HBS Tool",
    description:
      "HBS Tool is Apache-2.0 with the Commons Clause: free to use, fork and build around, even commercially. Only reselling the software itself is off limits.",
  },
];

// one page per doc section so deep links serve real HTML; the default
// section is additionally served at /docs (see pages[1] above).
for (const s of DOC_SECTIONS) {
  pages.push({
    path: `/docs/${s.slug}`,
    file: `docs/${s.slug}/index.html`,
    title: `${s.title} | HBS Tool docs`,
    description: `${s.blurb} Full HBS Tool documentation.`,
  });
}

// react-router warns about useLayoutEffect during SSR; harmless here (static
// snapshot, client re-renders fresh), so keep output clean.
const origError = console.error;
console.error = (...args: unknown[]) => {
  if (String(args[0]).includes("useLayoutEffect")) return;
  origError(...args);
};

try {
  // Load the layout and pages (NOT src/main.tsx - it calls createRoot at
  // import time, which has no DOM in Node) and mirror its route table.
  const { default: App } = await vite.ssrLoadModule("/src/App.tsx");
  const { default: Home } = await vite.ssrLoadModule("/src/pages/Home.tsx");
  const { default: Docs } = await vite.ssrLoadModule("/src/pages/Docs.tsx");
  const { default: Examples } = await vite.ssrLoadModule("/src/pages/Examples.tsx");
  const { default: About } = await vite.ssrLoadModule("/src/pages/About.tsx");
  const { default: License } = await vite.ssrLoadModule("/src/pages/License.tsx");
  const { default: NotFound } = await vite.ssrLoadModule("/src/pages/NotFound.tsx");

  // fileURLToPath, not URL#pathname: pathname keeps %20-style escapes and this
  // checkout may live under a path with spaces.
  const dist = resolve(dirname(fileURLToPath(import.meta.url)), "../dist");
  const shell = await readFile(resolve(dist, "index.html"), "utf8");
  if (!shell.includes('<div id="root"></div>')) {
    throw new Error("root div placeholder not found in dist/index.html");
  }

  const routeTable: [Page, React.ComponentType][] = [
    [pages[0], Home],
    [pages[1], Docs],
    [pages[2], Examples],
    [pages[3], About],
    [pages[4], License],
  ];
  for (const s of DOC_SECTIONS) {
    const p = pages.find((x) => x.path === `/docs/${s.slug}`);
    if (p) routeTable.push([p, Docs]);
  }
  routeTable.push([
    { path: "/404", file: "404.html", title: "Page not found | HBS Tool", description: "Page not found." },
    NotFound,
  ]);

  for (const [page, Component] of routeTable) {
    const html = renderToString(
      e(React.StrictMode, null,
        e(MemoryRouter, { initialEntries: [page.path] },
          e(Routes, null,
            e(Route, { path: "/", element: e(App) },
              e(Route, { index: true, element: e(Home) }),
              e(Route, { path: "docs", element: e(Docs) }),
              e(Route, { path: "docs/:section", element: e(Docs) }),
              e(Route, { path: "examples", element: e(Examples) }),
              e(Route, { path: "about", element: e(About) }),
              e(Route, { path: "license", element: e(License) }),
              e(Route, { path: "*", element: e(NotFound) })
            )
          )
        )
      )
    );
    void Component;

    const canon = `${CANON}${page.path === "/" ? "/" : `${page.path}/`}`;
    let out = shell.replace('<div id="root"></div>', `<div id="root">${html}</div>`);
    out = out
      .replace(/<title>.*?<\/title>/, `<title>${page.title}</title>`)
      .replace(
        /<meta name="description" content="[^"]*"/,
        `<meta name="description" content="${page.description.replace(/"/g, "&quot;")}"`
      )
      .replace(/<link rel="canonical" href="[^"]*"/, `<link rel="canonical" href="${canon}"`)
      .replace(/<meta property="og:url" content="[^"]*"/, `<meta property="og:url" content="${canon}"`);

    const target = resolve(dist, page.file);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, out);
  }

  // sitemap from the same route table so it can never drift from what is
  // actually emitted; directory (trailing-slash) URLs, the canonical form.
  const sitemap =
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n` +
    pages
      .map((p) => {
        const loc = `${CANON}${p.path === "/" ? "/" : `${p.path}/`}`;
        return `  <url><loc>${loc}</loc><changefreq>weekly</changefreq><priority>${p.path === "/" ? "1.0" : "0.6"}</priority></url>`;
      })
      .join("\n") +
    `\n</urlset>\n`;
  await writeFile(resolve(dist, "sitemap.xml"), sitemap);

  await vite.close();
  console.log(`[prerender] ${routeTable.length} routes + sitemap rendered to ${dist}`);
} catch (err) {
  await vite.close();
  throw err;
}

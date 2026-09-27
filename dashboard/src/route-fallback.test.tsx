import { describe, expect, it } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { PageFallback } from "./App";

/**
 * The route fallback must not paint a spinner on its first render.
 *
 * Route chunks are small and cached after the first visit, so rendering the
 * spinner immediately made every navigation flash one, including navigations
 * with nothing to wait for. The component holds the spinner back behind a
 * timer first; if someone removes that gate, this fails.
 */
describe("route fallback", () => {
  it("does not show a spinner on the first paint", () => {
    const html = renderToStaticMarkup(<PageFallback />);
    expect(html).not.toContain("animate-spin");
    expect(html).not.toContain("Loading page");
  });

  it("reserves the height so the page cannot collapse while blank", () => {
    const html = renderToStaticMarkup(<PageFallback />);
    expect(html).toContain("min-h-[280px]");
    expect(html).toContain('aria-busy="true"');
  });
});

# Sensor Release Tracker (UI page)

React + Vite page, started from the [Foundry React blueprint](https://github.com/CrowdStrike/foundry-js-blueprint-react), that renders the `sensor_release_tracker` collection as a dashboard: current build per platform and standing, filters, and the standing history of each build.

## Develop

```bash
pnpm install
pnpm watch        # rebuild src/dist on change; pair with `foundry ui run` from the app root
```

Opened outside the Falcon console (for example `src/dist/index.html` behind any static server) the page waits 3 seconds for `falcon.connect()`, then renders sample data behind a "Preview mode" banner. Live data needs the console.

## Build before deploying

`manifest.yml` serves `src/dist` as-is and `foundry apps deploy` does not build, so run `pnpm build` and commit `src/dist` before deploying. CI fails if the committed `src/dist` does not match the source.

## Layout

| Path | What |
|------|------|
| `src/app.jsx` | Bootstraps `FalconApi`, routes everything to `Home` |
| `src/contexts/falcon-api-context.js` | `connect()` with the preview-mode timeout |
| `src/hooks/use-sensor-releases.js` | Loads the collection (batched reads) or the sample data |
| `src/routes/home.jsx` | Page layout: platform cards, filters, sortable table |
| `src/components/` | Icons, badges, standing-history timeline |
| `src/lib/` | Platform/standing/stage constants, sample data, formatting helpers |
| `src/styles.css` | Badge variants and scrollbar on top of Toucan tokens |

## Styling notes

- Toucan ships prebuilt CSS, so responsive prefixes (`sm:`, `md:`) and arbitrary values (`max-h-[55vh]`) are no-ops. Use `flex-wrap`, inline `gridTemplateColumns`, or inline styles instead.
- Icons are inline SVG: the sandboxed iframe's CSP blocks the Shoelace icon CDN.
- Downloads and `window.open` are blocked in the iframe, so "Copy JSON" writes to the clipboard.

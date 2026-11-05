# Sensor Release Tracker (UI page)

The app's homepage in the Falcon console. It reads the `sensor_release_tracker`
collection and shows the current N / N-1 / N-2 build per platform, a
filterable, sortable table of every tracked build, and each build's standing
history.

Built with React, [foundry-js](https://github.com/CrowdStrike/foundry-js),
[Falcon Shoelace](https://github.com/CrowdStrike/falcon-shoelace) and
[Tailwind Toucan Base](https://github.com/CrowdStrike/tailwind-toucan-base),
starting from the [Foundry React blueprint](https://github.com/CrowdStrike/foundry-js-blueprint-react).

## Layout

| Path | Purpose |
|------|---------|
| `src/app.jsx` | Connects to Falcon and renders the page |
| `src/contexts/falcon-api-context.js` | Creates and connects the `FalconApi` instance |
| `src/routes/home.jsx` | The dashboard |
| `src/components/icons.jsx` | Inline SVG icons |
| `src/styles.css` | Badge colors built from Toucan status tokens |
| `src/dist/` | Build output. **This is what Foundry deploys** -- it is committed |

`vite.config.js` is the blueprint's, unchanged; Foundry's sandboxed iframe
depends on it.

## Develop

This project uses [pnpm](https://pnpm.io/installation).

```bash
pnpm install
pnpm watch   # rebuilds src/dist on every change
```

Then run `foundry ui run` from the **app root** and enable Development mode in
the Falcon console's Developer tools.

Opened outside the console (for example `src/dist/index.html` served locally),
the page gives up waiting for Falcon after 3 seconds and shows sample data
under a "Preview mode" banner.

## Build before deploying

Foundry deploys `src/dist` as-is and never builds the UI, so rebuild and commit
it after every source change:

```bash
pnpm build
```

## Notes

- Shoelace components are imported one at a time
  (`@shoelace-style/shoelace/dist/react/<name>/index.js`). Importing the
  `@shoelace-style/shoelace/dist/react` barrel registers every component and
  more than doubles the bundle.
- The prebuilt Toucan CSS has no responsive (`sm:`/`md:`) or arbitrary-value
  (`max-h-[55vh]`) classes, so the page uses inline styles for those.
- The sandboxed iframe blocks web storage and `alert`/`confirm`, so state is
  kept in memory and errors are shown inline.

# Dependency Notes

This file documents *why* each pinned floor was chosen — package.json and
requirements.txt can't hold inline reasoning, so it lives here. Regenerated
and verified 2026-07 in clean environments (Python 3.12 venv, Node 22/npm 10).

## Python (`backend/requirements.txt`)

All floors verified together in a clean Python 3.12 virtualenv: `pip install
-r requirements.txt` completes with zero conflicts (`pip check` passes), and
the actual application (`import main`) loads successfully end-to-end — not
just the individual packages in isolation.

**Removed as unused** (confirmed via an AST-based scan of every import
statement in every `.py` file under `backend/`, not a text grep):
- `aiofiles` — never imported anywhere in the codebase.
- `pydantic-settings` — never imported; nothing uses `BaseSettings`.

**Hard compatibility constraint — yara-python vs. Python version:**
yara-python 4.5.4 (latest) publishes prebuilt wheels for CPython 3.9–3.13
only. There is no Python 3.14 wheel yet, so `pip install` on 3.14 falls back
to a source build requiring a C++ compiler (MSVC Build Tools on Windows).
This is a **Python-version** constraint, not a package-version one — no
yara-python version fixes it until upstream publishes cp314 wheels. Use
Python 3.12 or 3.13 for a zero-compiler install, or install the Build Tools
if you need 3.14. The app degrades gracefully without yara-python installed
(YARA matching disabled; heuristics and all threat-intel providers still work).

No other Python package required a version ceiling — everything else
resolves to its current latest release with no conflicts.

## npm (`package.json`)

Every dependency here is actually imported somewhere in `src/` — none were
found unused. Full resolution verified with `npm install` + `npm ls` (clean
peer-dependency tree, single deduped React instance) in Node 22 / npm 10.

**Kept at major v3, NOT upgraded to v4 — `tailwindcss`:**
Tailwind v4 is a ground-up rewrite (Rust/Oxide engine). It drops
`tailwind.config.js` as the source of truth in favor of CSS-native `@theme`
blocks, and removes `tailwindcss` as a direct PostCSS plugin (replaced by
`@tailwindcss/postcss` or `@tailwindcss/vite`). This project's
`tailwind.config.js` (JS-based theme extension, CSS-variable color tokens)
and `postcss.config.js` (`tailwindcss: {}` as a direct plugin) are both v3-
style and would break outright on v4 without a dedicated migration. Pinned
to the latest v3.4.x patch instead of jumping majors silently.

**Bumped to latest major — `vite` (^5.4.12, not a 6/7/8 jump):**
`npm audit` flags two things on this dependency tree:
1. **Real, exploitable — already fixed by this floor.** Vite's own
   CVE-2025-24010 (GHSA-vg6x-rcgg-rjx6: default dev-server CORS + missing
   Origin/Host validation, allowing any website to query the local dev
   server) was patched in-place in the 5.4.x line starting at **5.4.12** —
   no major version bump required. Confirmed: this advisory no longer
   appears in `npm audit` output once the floor is raised to 5.4.12+
   (verified installed version: 5.4.21).
2. **Remaining flag — not applicable here.** `esbuild <=0.24.2`
   (GHSA-67mh-4wv8-2f99) is still flagged because Vite 5.x (and even 6.x up
   to 6.4.2) bundles an esbuild version below the patched line; a fully
   clean `npm audit` requires Vite 6.4.3+ or 8.0.5+. Vite's own maintainers
   have stated this specific advisory does not apply to normal Vite usage,
   since Vite never exposes esbuild's own `serve()` API (the actual
   vulnerable surface) — Vite runs its own dev server. Left un-upgraded
   deliberately rather than making an unverified 1–3 major-version jump;
   revisit as its own dedicated migration if a fully clean audit is required.

**Bumped to latest major — `recharts` (^3.0.0, was ^2.12.0):**
The recharts maintainers have publicly declared the 1.x/2.x branches no
longer actively maintained and recommend v3 (this appears as an npm install
warning, not just an audit note). Verified the specific exports this
codebase uses (`AreaChart`, `Area`, `XAxis`, `YAxis`, `CartesianGrid`,
`Tooltip`, `ResponsiveContainer` — all used in `SystemGraph.jsx`) still
exist as valid components in v3.10.0. This is an import-level check, not a
rendered-output check — **spot-check the System Activity chart visually
after upgrading**, since v3 changed internal implementation details (it now
pulls in `@reduxjs/toolkit`/`react-redux` as internal state management).

**Bumped to latest major — `framer-motion` (^12.0.0, was ^11.0.0):**
Framer Motion was renamed to `motion` upstream in 2025, but the legacy
`framer-motion` package name is still published and functional (current:
12.42.2) — no import-path changes required to stay on it. The APIs this
codebase uses (`motion.div`, `AnimatePresence`, `initial`/`animate`/`exit`/
`transition`/`layoutId`/`whileHover`/`whileTap`) are foundational and have
been stable across major versions. Recommend a visual spot-check of modal/
toast/panel transitions after upgrading, same as recharts, since animation
libraries can have subtle per-version easing/timing differences even when
the API surface itself doesn't change.

**Kept at major v18, deliberately NOT upgraded to React 19 — `react` /
`react-dom`:**
React 19 is current upstream (19.2.8), but this was a deliberate choice to
avoid stacking an unverified React major-version bump on top of the
recharts v3 and framer-motion v12 bumps in the same pass — three
simultaneous major upgrades to peer-dependent libraries is exactly the kind
of change that should be tested individually, not bundled. React 18 is
still fully supported upstream, so this isn't a "stuck on outdated" pin —
it's sequencing. Revisit as a separate, dedicated upgrade once v3/v12 are
confirmed stable in this app.

**Found and fixed — broken production build (`vite.config.js`):**
`build.minify` was set to `'terser'`, but `terser` was never listed in
`devDependencies`. Vite made terser an *optional* dependency starting in v3
— using it without installing it fails the build outright:
`[vite:terser] terser not found. Since Vite v3, terser has become an
optional dependency. You need to install it.` Confirmed by actually running
`vite build` in a clean environment. Since `Dockerfile.frontend` runs
`npm run build` in its builder stage, this meant **the Docker/production
build path was broken** regardless of which dependency versions were
pinned. Fixed by switching to `minify: 'esbuild'` (Vite's built-in default
since v3 — no extra package needed); verified a clean `vite build` now
succeeds. This wasn't a version-pin issue, just a missing dependency for a
non-default option — worth calling out since "does it actually build"
matters as much as "does it install."

**Routine floor bumps (no compatibility concerns found):**
`react-circular-progressbar` -> ^2.2.0 (latest; peer dep is `react >=0.14.0`,
trivially satisfied), `@vitejs/plugin-react` -> ^4.3.4 (latest 4.x, matches
Vite 5's plugin API), `autoprefixer` -> ^10.4.20, `postcss` -> ^8.4.47.

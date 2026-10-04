# Design

Cert Generator is set like a **bound register of issued documents**: an engraved
certificate on the sign-in page, a ledger of authorities and certificates inside.
Everything visual should feel printed and ruled, not like a generic web dashboard.

Read this before changing any UI, in the web app (`app/static`, `app/templates`)
or in Cert Generator Pal (`pal/src/CertGeneratorPal/Theme.cs`).

## The look in one line

Serif display type, mono data, brass accent, square corners, strong rules
instead of cards and shadows.

## Type

| Role | Font | Where |
|---|---|---|
| Display | Libre Caslon Display (Georgia in Pal) | Page titles, card headings, dialog titles |
| Body | Libre Caslon Text | Running text, list items, names |
| Data | `--font-mono` (Cascadia Mono / Consolas in Pal) | Serials, fingerprints, dates, hostnames, counts |
| Labels | Mono, 9.5–11px, uppercase, letter-spacing 0.12–0.22em | Eyebrows, buttons, table status, section labels |
| UI | Segoe UI / system sans | Sign-in form controls only |

- Field labels in ledgers are *italic serif* ("Type", "Expires"), values are mono.
- Never introduce Inter, Roboto, Poppins or any other web-default sans.

## Colour

All colours are tokens in `app/static/theme.css`; never hardcode a hex in a
component. Six themes: Slate (default) and Flashbang (light); OLED, Graphite,
Umber and Ink (dark).

**Accent: brass** `#d4a017`. Use it for primary actions, the active item's inset bar
and eyebrow labels. Text in the accent hue uses `--accent-text` (the AA-safe shade);
tints derive from `var(--accent)` with `color-mix`, so a custom accent still works.

**Status inks** are pigments chosen to sit beside brass:

| Token | Light (Slate, Flashbang) | Dark (OLED, Graphite, Umber, Ink) |
|---|---|---|
| `--success` | `#2d6a45` bottle green | `#8fc29a` sage |
| `--danger` | `#9e2a2b` oxblood | `#e8877c` madder |
| `--warning` | `#9a4a1a` sienna | `#e39a6b` terracotta |

All of them clear WCAG AA (4.5:1) as text on every theme's background and surface.
Text on a solid danger fill uses `--on-danger`. Warning must stay clearly redder
than brass, so it is never mistaken for the accent.

**Accent presets** are named pigments (Vermilion, Oxblood, Madder, Tyrian,
Indigo dye, Prussian, Verdigris, Viridian, Olive, Sepia, Pewter). Name any new
preset the same way.

## Shape and depth

- Corners are square: `border-radius: 0` (`--radius: 2px` only for small inputs).
  The only round shapes are status dots and colour swatches.
- Separate things with **rules**: 1px `--border` for hairlines, `--rule` for strong
  section lines, the double rule under card headings, and `outline` inset by 5–7px
  for a framed, engraved edge on dialogs and popovers.
- Floating layers (menus, dialogs, toasts, popovers) get `--shadow`: a hard
  4px offset with no blur, like a sheet of paper on a desk. Never use a soft
  blurred shadow.
- The selected item gets an inset 3px accent bar (`box-shadow: inset 3px 0 0`),
  not a filled pill.

## Components

- **Buttons:** square, 1px border, uppercase mono label. Kinds: primary (brass fill),
  ghost (rule border), danger (oxblood outline, filled on hover). No icons-only
  buttons without a label or `aria-label`.
- **Cards:** a heading in display serif over a double rule, then content inset 20px.
  No rounded card grid.
- **Tables:** the certificate register. Italic serif headers, mono data, uppercase
  mono status words in the status inks, a strike-through for revoked rows.
- **Notes and steps:** a 3–4px coloured left rule plus an uppercase mono label
  (e.g. ENDPOINT-HOSTED CRL), not a coloured box with an icon.

## Never

These are the tells of generic AI-generated UI. Don't use them here:

- Tailwind default colours (`#22c55e`, `#ef4444`, `#3b82f6`, `#6366f1`…) or any
  purple-to-blue gradient
- Rounded cards, pill buttons, `border-radius` over 2px
- Soft blurred drop shadows or glassmorphism (`backdrop-filter: blur`)
- Emoji or decorative icon sets as section markers
- Centred hero headings with a gradient word, "✨" badges, or stat tiles with big numbers
- Inter, or system sans in body text

## Pal

`Theme.cs` mirrors the web app: Slate when Windows is in light mode, Ink when it is
dark, the same tokens, brass accent, Georgia for display and Cascadia Mono / Consolas
for data. When a token changes in `theme.css` (Slate or Ink), change it in
`Theme.cs` in the same commit.

## Checking a change

Before a UI change ships, look at every touched screen in Slate and Ink at
1440px desktop and ~390px phone, and check that no page scrolls sideways.
New colours need a contrast check against each theme's `--bg` and `--surface`.

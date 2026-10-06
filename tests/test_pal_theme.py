"""The Pal's themes are the web app's: DESIGN.md says a token changed in theme.css changes in Theme.cs too."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOKENS = ["bg", "surface", "surface-hover", "border", "rule", "text", "text-dim", "accent-text"]
STATUS = {"success": "Success", "danger": "Danger", "warning": "Warning"}


def _css_themes():
    css = (ROOT / "app/static/theme.css").read_text(encoding="utf-8")
    themes = {}
    for name, body in re.findall(r':root\[data-theme="(\w+)"\]\s*\{(.*?)\n\}', css, re.S):
        themes[name] = dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6})\s*;", body))
    return themes


def _pal_source():
    return (ROOT / "pal/src/CertGeneratorPal/Theme.cs").read_text(encoding="utf-8")


def test_pal_has_every_theme_with_the_same_tokens():
    css = _css_themes()
    pal = {
        name.lower(): (dark == "true", re.findall(r'"(#[0-9a-fA-F]{6})"', colours))
        for name, dark, colours in re.findall(r'new\("(\w+)", (true|false), ([^)]*)\)', _pal_source())
    }
    assert set(pal) == set(css) and len(css) == 6
    for name, (_, colours) in pal.items():
        assert colours == [css[name][token] for token in TOKENS], name


def test_pal_status_inks_match_light_and_dark():
    css, source = _css_themes(), _pal_source()
    dark = {name.lower() for name, flag in re.findall(r'new\("(\w+)", (true|false),', source) if flag == "true"}
    for token, field in STATUS.items():
        dark_ink, light_ink = re.search(rf'{field} = Dark \? Hex\("(#\w+)"\) : Hex\("(#\w+)"\)', source).groups()
        for name, tokens in css.items():
            assert tokens[token] == (dark_ink if name in dark else light_ink), (name, token)

# Shared settings for the README demo tapes. Run docs/demo/setup.sh first;
# tapes are run from the repo root: vhs docs/demo/<name>.tape
#
# Each tape sets PATH to /tmp/rpt-demo/bin:/usr/bin:/bin in its hidden
# setup, so only the demo's rpt and plugin show up (Env PATH would also
# hide ttyd from vhs).
Require jq

Set Shell "bash"
Set FontFamily "JetBrainsMono Nerd Font Mono"
Set FontSize 20
Set Width 1440
Set Height 560
Set Padding 24
Set TypingSpeed 70ms
Set Theme "Catppuccin Mocha"

Env COLORTERM "truecolor"
Env RPT_REPORT_DIR ""

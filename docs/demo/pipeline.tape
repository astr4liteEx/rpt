Output docs/demo/pipeline.gif
# rpt verbs lists every built-in before the plugin: a wider, taller frame.
Set Width 2180
Set Height 800
Source docs/demo/common.tape

Hide
Type "export PATH=/tmp/rpt-demo/bin:/usr/bin:/bin; PS1='$ '; set -o pipefail; cd /tmp/rpt-demo/pipeline/acme-external; clear"
Enter
Show

Type "cat ../scan.csv"
Sleep 300ms
Enter
Sleep 2.5s
Type "rpt verbs"
Sleep 300ms
Enter
Sleep 2.5s
Type "rpt parse-scan < ../scan.csv | rpt scope match --drop-out-of-scope | rpt finding add"
Sleep 300ms
Enter
Sleep 4s
Hide

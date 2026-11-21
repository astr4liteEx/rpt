Output docs/demo/pipeline.gif
Set Width 1440
Set Height 620
Source docs/demo/common.tape

Hide
Type "export PATH=/tmp/rpt-demo/bin:/usr/bin:/bin; PS1='$ '; set -o pipefail; cd /tmp/rpt-demo/pipeline/acme-external; clear"
Enter
Show

Type "cat ../scan.csv"
Sleep 300ms
Enter
Sleep 2.5s
Type "rpt help parse-scan"
Sleep 300ms
Enter
Sleep 2.5s
Type "rpt parse-scan < ../scan.csv | rpt scope match --drop-out-of-scope | rpt finding add"
Sleep 300ms
Enter
Sleep 4s
Hide

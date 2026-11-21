Output docs/demo/quick-start.gif
Set Width 1440
Set Height 720
Source docs/demo/common.tape

Hide
Type "export PATH=/tmp/rpt-demo/bin:/usr/bin:/bin; PS1='$ '; cd /tmp/rpt-demo/start; clear"
Enter
Show

Type "rpt new acme-external && cd acme-external && ls"
Sleep 300ms
Enter
Sleep 1.5s
Type "rpt scope add --id S-12 --host 10.0.0.5 --port 443 --protocol tcp"
Sleep 300ms
Enter
Sleep 1s
Type "rpt scope add --id S-14 --host 10.0.0.6 --port 8443 --protocol tcp"
Sleep 300ms
Enter
Sleep 1s
Type "rpt finding add < ../findings.jsonl"
Sleep 300ms
Enter
Sleep 2.5s
Type "rpt validate && echo clean"
Sleep 300ms
Enter
Sleep 3s
Hide

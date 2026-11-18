Output docs/demo/quick-start.gif
Source docs/demo/common.tape

Hide
Type "export PATH=/tmp/rpt-demo/bin:/usr/bin:/bin; PS1='$ '; cd /tmp/rpt-demo/start; clear"
Enter
Show

Type "rpt new acme-external && cd acme-external && ls"
Sleep 300ms
Enter
Sleep 1.5s
Type "echo 'S-12,10.0.0.5,443,tcp' >> scope.csv"
Sleep 300ms
Enter
Sleep 600ms
Type "echo 'S-14,10.0.0.6,8443,tcp' >> scope.csv"
Sleep 300ms
Enter
Sleep 800ms
Type "rpt add < ../findings.jsonl"
Sleep 300ms
Enter
Sleep 2.5s
Type "rpt validate && echo clean"
Sleep 300ms
Enter
Sleep 3s
Hide

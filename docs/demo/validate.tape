Output docs/demo/validate.gif
Set Width 1440
Set Height 560
Source docs/demo/common.tape

Hide
Type "export PATH=/tmp/rpt-demo/bin:/usr/bin:/bin; PS1='$ '; cd /tmp/rpt-demo/validate/acme-external; clear"
Enter
Show

Type "rpt validate"
Sleep 300ms
Enter
Sleep 3s
Type "rpt finding set F-002 targets S-14"
Sleep 300ms
Enter
Sleep 2s
Type "rpt validate && echo clean"
Sleep 300ms
Enter
Sleep 2s
Type "rpt assemble | jq -c .summary"
Sleep 300ms
Enter
Sleep 3s
Hide

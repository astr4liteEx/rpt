#!/usr/bin/env bash
# setup.sh rebuilds the scratch data the README demo tapes record against,
# in /tmp/rpt-demo (wiped first, so each recording starts the same). Run it
# from anywhere before each `vhs docs/demo/<name>.tape`. Nothing outside
# /tmp/rpt-demo is touched. Needs go and jq.
set -euo pipefail
cd "$(dirname "$0")/../.."

demo=/tmp/rpt-demo
rm -rf "$demo"
mkdir -p "$demo/bin" "$demo/start" "$demo/validate" "$demo/pipeline"

CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$demo/bin/rpt" ./cmd/rpt
rpt=$demo/bin/rpt

# rpt-parse-scan stands in for a scanner importer plugin: it turns a
# host,port,severity,title CSV into finding records with a target host;
# rpt scope match attributes each to a scope row.
cat > "$demo/bin/rpt-parse-scan" <<'EOF'
#!/usr/bin/env bash
if [ "${1-}" = --describe ]; then
	echo '{"summary":"Import a scanner CSV export as finding records","usage":"rpt parse-scan < scan.csv","input":"csv/scan","output":"records"}'
	exit 0
fi
tail -n +2 | while IFS=, read -r host port sev title; do
	jq -cn --arg h "$host" --argjson p "$port" --arg s "$sev" --arg t "$title" \
		'{kind:"finding",title:$t,severity:$s,targets:[{host:$h,port:$p,protocol:"tcp"}],
		  sections:{description:"Reported by the scanner.",remediation:"See the vendor advisory.",poc:"Scanner output."}}'
done
EOF
chmod +x "$demo/bin/rpt-parse-scan"

# finding TITLE SEVERITY TARGETS DESCRIPTION REMEDIATION POC
finding() {
	jq -cn --arg t "$1" --arg s "$2" --argjson sc "$3" --arg d "$4" --arg r "$5" --arg p "$6" \
		'{kind:"finding",title:$t,severity:$s,targets:$sc,sections:{description:$d,remediation:$r,poc:$p}}'
}
findings() {
	finding "SQL injection in login" high '[{"scope":"S-12"}]' \
		"The user parameter of /login is concatenated into a SQL query." \
		"Use parameterised queries." "user=' OR 1=1-- logs in as the first user."
	finding "Reflected XSS in search" medium '[{"scope":"S-14"}]' \
		"The q parameter is reflected unescaped." "Encode output." "/search?q=<script>alert(1)</script>"
	finding "TLS 1.0 enabled" low '[{"scope":"S-12"}]' \
		"The server accepts TLS 1.0." "Disable TLS 1.0 and 1.1." "nmap --script ssl-enum-ciphers -p 443 10.0.0.5"
}
scope_rows='S-12,10.0.0.5,443,tcp
S-14,10.0.0.6,8443,tcp
S-20,10.0.1.0/24,,'

# quick-start: an empty working folder, with the findings to import beside it.
findings > "$demo/start/findings.jsonl"

# validate: a report with one planted problem, F-002 citing a scope row
# that doesn't exist.
"$rpt" new "$demo/validate/acme-external"
printf '%s\n' "$scope_rows" >> "$demo/validate/acme-external/scope.csv"
findings | "$rpt" findings add --report "$demo/validate/acme-external" > /dev/null
"$rpt" findings set --report "$demo/validate/acme-external" F-002 targets '[{scope: S-99}]' > /dev/null

# pipeline: a report with scope and no findings, and a scan export beside it
# (one host, 192.168.9.9, is out of scope).
"$rpt" new "$demo/pipeline/acme-external"
printf '%s\n' "$scope_rows" >> "$demo/pipeline/acme-external/scope.csv"
cat > "$demo/pipeline/scan.csv" <<'EOF'
host,port,severity,title
10.0.0.5,443,high,Outdated OpenSSL with known CVEs
10.0.1.17,22,medium,SSH allows password logins
192.168.9.9,80,low,Directory listing enabled
10.0.0.6,8443,low,Missing security headers
EOF

echo "demo data in $demo:"
echo "  start/     empty folder and findings.jsonl (quick-start.tape)"
echo "  validate/  acme-external with one planted problem (validate.tape)"
echo "  pipeline/  acme-external with scope only, and scan.csv (pipeline.tape)"

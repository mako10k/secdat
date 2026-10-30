set -e
[[ $(command -v secdat) == /usr/local/bin/secdat ]]
[[ $(secdat --version | head -n1) == 'secdat 0.11.0' ]]
declare -F _completion_loader >/dev/null
set +e
_completion_loader secdat
loader_status=$?
set -e
[[ $loader_status == 124 ]]
complete -p secdat
completion_definition=$(shopt -s extdebug; declare -F _secdat_complete)
[[ $completion_definition == *'/usr/local/share/bash-completion/completions/secdat' ]]
printf 'Loaded completion: %s\n' "$completion_definition"
fixture_root=${INSTALL_FIXTURE_ROOT:?}
parent_domain="$fixture_root/domains/parent"
child_domain="$parent_domain/child"
mkdir -p "$child_domain"
secdat --dir "$parent_domain" domain create >/dev/null
secdat --dir "$child_domain" domain create >/dev/null
secdat --dir "$parent_domain" store create app-parent >/dev/null
secdat --dir "$child_domain" store create app-child >/dev/null
secdat --dir "$child_domain" store create 'app space' >/dev/null
snapshot() {
 python3 - "$XDG_DATA_HOME" <<'PY'
import hashlib,pathlib,sys
p=pathlib.Path(sys.argv[1]);h=hashlib.sha256()
for f in sorted(p.rglob('*')):
 if f.is_file(): h.update(str(f.relative_to(p)).encode()+b'\0'+f.read_bytes())
print(h.hexdigest())
PY
}
state_before=$(snapshot)
assert_reply() {
 local label=$1 expected=$2
 local actual
 actual=$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1:]))' "${COMPREPLY[@]}")
 [[ $actual == "$expected" ]] || { printf 'FAIL %s: %s\n' "$label" "$actual"; return 1; }
 printf 'PASS %s: %s\n' "$label" "$actual"
}
COMP_WORDS=(secdat --dir "$child_domain" --store app)
COMP_CWORD=4
COMP_LINE="secdat --dir $child_domain --store app"
COMP_POINT=${#COMP_LINE}
_secdat_complete
assert_reply 'inherited store completion' '["app\\ space", "app-child", "app-parent"]'
COMP_WORDS=(secdat --dir "$child_domain" store delete app)
COMP_CWORD=5
COMP_LINE="secdat --dir $child_domain store delete app"
COMP_POINT=${#COMP_LINE}
_secdat_complete
assert_reply 'local management store completion' '["app\\ space", "app-child"]'
COMP_WORDS=(secdat --dir "$child_domain" --store=app)
COMP_CWORD=3
COMP_LINE="secdat --dir $child_domain --store=app"
COMP_POINT=${#COMP_LINE}
_secdat_complete
assert_reply 'attached store completion' '["--store=app\\ space", "--store=app-child", "--store=app-parent"]'
COMP_WORDS=(secdat --dir "$child_domain" store create app)
COMP_CWORD=5
COMP_LINE="secdat --dir $child_domain store create app"
COMP_POINT=${#COMP_LINE}
_secdat_complete
assert_reply 'create does not suggest existing stores' '[]'
[[ $(snapshot) == "$state_before" ]]
printf 'PASS completion leaves fixture state unchanged\n'

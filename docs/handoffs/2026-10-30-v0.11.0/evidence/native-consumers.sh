#!/usr/bin/env bash
set -euo pipefail
EVIDENCE_DIR=/home/katsumata-m/secdat-release-evidence/v0.11.0
export EVIDENCE_DIR
unset PKG_CONFIG_SYSROOT_DIR
source_root=/home/katsumata-m/secdat-release-0.11.0
archive="$source_root/secdat-0.11.0.tar.gz"
test -f "$archive"
cp "$archive" "$EVIDENCE_DIR/secdat-0.11.0.tar.gz"
python3 - <<'PY'
import hashlib,json,pathlib,subprocess,tarfile
base=pathlib.Path('/home/katsumata-m/secdat-release-evidence/v0.11.0')
root=pathlib.Path('/home/katsumata-m/secdat-release-0.11.0')
archive=base/'secdat-0.11.0.tar.gz'
tracked=subprocess.check_output(['git','-C',str(root),'ls-files','-z']).decode().split('\0')
checked=[]
with tarfile.open(archive) as tar:
 names=set(tar.getnames())
 for path in filter(None,tracked):
  name='secdat-0.11.0/'+path
  if name in names and tar.getmember(name).isfile():
   data=tar.extractfile(name).read()
   expected=subprocess.check_output(['git','-C',str(root),'show','HEAD:'+path])
   assert data==expected, f'Distribution differs from candidate: {path}'
   checked.append(path)
 assert 'docs/release-notes/v0.11.0.md' in checked
 assert 'src/store.c' in checked and 'bindings/node/package.json' in checked
 target=base/'distribution'
 target.mkdir(exist_ok=False)
 tar.extractall(target,filter='data')
(base/'archive-provenance.json').write_text(json.dumps({'candidate':json.loads((base/'candidate.json').read_text()),'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'tracked_shipped_files_verified':checked},indent=2)+'\n')
print('Distribution provenance PASS',len(checked),'tracked shipped files')
PY
export RELEASE_SOURCE="$EVIDENCE_DIR/distribution/secdat-0.11.0"
export SHARED_PREFIX="$EVIDENCE_DIR/prefix-shared"
export STATIC_PREFIX="$EVIDENCE_DIR/prefix-static"
test ! -e "$SHARED_PREFIX"
test ! -e "$STATIC_PREFIX"
mkdir "$EVIDENCE_DIR/build-shared" "$EVIDENCE_DIR/build-static"
(
 cd "$EVIDENCE_DIR/build-shared"
 "$RELEASE_SOURCE/configure" --enable-fuse --enable-shared --enable-static --prefix="$SHARED_PREFIX"
 make -j2
 make install
)
(
 cd "$EVIDENCE_DIR/build-static"
 "$RELEASE_SOURCE/configure" --enable-fuse --disable-shared --enable-static --prefix="$STATIC_PREFIX"
 make -j2
 make install
)
cat > "$EVIDENCE_DIR/consumer.c" <<'C'
#include <secdat-sdk.h>
int main(void) { secdat_sdk_free(0); return 0; }
C
for shape in shared static; do
 if test "$shape" = shared; then stage_prefix="$SHARED_PREFIX"; else stage_prefix="$STATIC_PREFIX"; fi
 export PKG_CONFIG_PATH=''
 export PKG_CONFIG_LIBDIR="$stage_prefix/lib/pkgconfig"
 test "$(pkg-config --variable=pcfiledir libsecdat)" = "$stage_prefix/lib/pkgconfig"
 test "$(pkg-config --variable=prefix libsecdat)" = "$stage_prefix"
 test "$(pkg-config --modversion libsecdat)" = 0.11.0
 if test "$shape" = shared; then
  test -f "$stage_prefix/lib/libsecdat.so"
  flags_text=$(pkg-config --cflags --libs libsecdat)
 else
  test -f "$stage_prefix/lib/libsecdat.a"
  test ! -e "$stage_prefix/lib/libsecdat.so"
  flags_text=$(pkg-config --static --cflags --libs libsecdat)
 fi
 case " $flags_text " in *" -I$stage_prefix/include "*) ;; *) exit 1;; esac
 case " $flags_text " in *" -L$stage_prefix/lib "*) ;; *) exit 1;; esac
 read -r -a flags <<< "$flags_text"
 cc "$EVIDENCE_DIR/consumer.c" "${flags[@]}" -o "$EVIDENCE_DIR/consumer-$shape"
 readelf -d "$EVIDENCE_DIR/consumer-$shape" > "$EVIDENCE_DIR/consumer-$shape.dynamic"
 if test "$shape" = static; then
  if rg -F 'Shared library: [libsecdat.so' "$EVIDENCE_DIR/consumer-$shape.dynamic"; then exit 1; fi
 else
  rg -F 'Shared library: [libsecdat.so.0]' "$EVIDENCE_DIR/consumer-$shape.dynamic"
  LD_LIBRARY_PATH="$stage_prefix/lib" ldd "$EVIDENCE_DIR/consumer-$shape" > "$EVIDENCE_DIR/consumer-$shape.ldd"
  rg -F "$stage_prefix/lib/libsecdat.so.0" "$EVIDENCE_DIR/consumer-$shape.ldd"
 fi
 LD_LIBRARY_PATH="$stage_prefix/lib" "$EVIDENCE_DIR/consumer-$shape"
 LD_LIBRARY_PATH="$stage_prefix/lib" "$stage_prefix/bin/secdat" --version
 printf 'PASS installed %s C consumer\n' "$shape"
done

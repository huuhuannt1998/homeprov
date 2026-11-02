#!/bin/bash
# E11: build the two OSGi bundles (drafts/round13/E11_DESIGN.md, section 4) against the openHAB jars shipped in the
# pinned hub image, with a JDK in a container (the Mac has no JDK). Docker is used, so the E9/E10 guard applies.
#
#   build_bundles.sh OUTDIR
# Writes OUTDIR/org.homeprov.e11.fixture-1.0.0.jar, OUTDIR/org.homeprov.e11.lockbridge-1.0.0.jar (the instrument: only
# when testbed/e11/attack exists; it is never released) and OUTDIR/build.json (images, compile classpath with sha256,
# source and jar sha256). Jars are reproducible (fixed entry dates), so the same sources give the same jar sha256.
set -u
REPO="${ARTIFACT_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"; export ARTIFACT_ROOT="$REPO"
E11=$REPO/testbed/e11
OUT=${1:?usage: build_bundles.sh OUTDIR}
OH_IMG=${E11_OH_IMAGE:-openhab/openhab:5.2.3@sha256:fa50a6934dfd5bcbf21db18af66f2558f58c6c493ba23bdeb7a894e764507a99}
JDK_IMG=${E11_JDK_IMAGE:-eclipse-temurin:21-jdk}
DATE=2026-10-21T00:00:00Z
"$E11/e11_stack.sh" guard || exit 2
[ -e "$OUT/build.json" ] && { echo "REFUSING: $OUT/build.json exists"; exit 3; }
mkdir -p "$OUT/cp" "$OUT/work"
# 1. the compile classpath, copied out of the hub image (Karaf's system repository)
CID=$(docker create --entrypoint true "$OH_IMG") || exit 4
LIST=$(docker run --rm --entrypoint sh "$OH_IMG" -c 'cd /openhab/runtime/system && find . \( -name "org.openhab.core-[0-9]*.jar" \
  -o -name "org.openhab.core.persistence-[0-9]*.jar" -o -name "gson-[0-9]*.jar" -o -name "osgi.core-*.jar" \
  -o -name "org.apache.felix.framework-*.jar" -o -name "org.eclipse.jdt.annotation-*.jar" -o -name "unit-api-*.jar" \) \
  | sort') || exit 4
for f in $LIST; do docker cp "$CID:/openhab/runtime/system/${f#./}" "$OUT/cp/" >/dev/null || exit 4; done
docker rm "$CID" >/dev/null
CP=$(ls "$OUT"/cp/*.jar | tr '\n' ':')
[ -n "$CP" ] || { echo "no classpath jars found in $OH_IMG"; exit 4; }
# 2. a JDK: the hub image's own if it has javac, else the JDK image
if docker run --rm --entrypoint sh "$OH_IMG" -c 'command -v javac >/dev/null'; then JIMG=$OH_IMG; else
  docker image inspect "$JDK_IMG" >/dev/null 2>&1 || docker pull -q "$JDK_IMG" >/dev/null || exit 4; JIMG=$JDK_IMG; fi
BUNDLES="fixture:org.homeprov.e11.fixture"
[ -d "$E11/attack/src" ] && BUNDLES="$BUNDLES attack:org.homeprov.e11.lockbridge"
for b in $BUNDLES; do
  dir=${b%%:*}; bsn=${b##*:}
  docker run --rm --network none -v "$E11/$dir":/src:ro -v "$OUT":/out --entrypoint sh "$JIMG" -c "
    set -e; rm -rf /out/work/$dir && mkdir -p /out/work/$dir
    CP=\$(ls /out/cp/*.jar | tr '\n' ':')
    javac --release 21 -proc:none -nowarn -encoding UTF-8 -cp \"\$CP\" -d /out/work/$dir \$(find /src/src -name '*.java')
    jar --create --file /out/$bsn-1.0.0.jar --manifest /src/META-INF/MANIFEST.MF --date $DATE -C /out/work/$dir .
  " || { echo "build of $dir failed"; exit 5; }
done
"${PY:-<home>/miniconda3/bin/python3}" - "$OUT" "$OH_IMG" "$JIMG" "$E11" <<'PY'
import glob, hashlib, json, os, subprocess, sys
out, oh, jimg, e11 = sys.argv[1:]
h = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
img = lambda i: subprocess.run(["docker", "image", "inspect", i.split("@")[0], "--format", "{{.Id}} {{json .RepoDigests}}"],
                               capture_output=True, text=True).stdout.strip()
src = {os.path.relpath(p, e11): h(p) for d in ("fixture", "attack") for p in sorted(glob.glob(os.path.join(e11, d, "**", "*"),
       recursive=True)) if os.path.isfile(p)}
doc = {"hub_image": oh, "hub_image_inspect": img(oh), "jdk_image": jimg, "jdk_image_inspect": img(jimg),
       "classpath": {os.path.basename(p): h(p) for p in sorted(glob.glob(os.path.join(out, "cp", "*.jar")))},
       "sources_sha256": src, "jars_sha256": {os.path.basename(p): h(p) for p in sorted(glob.glob(os.path.join(out, "*.jar")))}}
json.dump(doc, open(os.path.join(out, "build.json"), "x"), indent=1)
print(json.dumps(doc["jars_sha256"]))
PY

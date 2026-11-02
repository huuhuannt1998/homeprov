"""Integrity-gate helper for R2 drivers: run exp/sp2027/r2_integrity.py and
return (written_path, passed). Lets each driver embed pre+post integrity paths
and validity directly in its result file (coordinator requirement)."""
import glob, os, subprocess, time
ROOT=os.environ.get("ARTIFACT_ROOT") or os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
INTD=os.path.join(ROOT,"exp","out","r2_integrity")
def run_integrity(rel, label, prev=None):
    cmd=["python3",os.path.join(ROOT,"exp","sp2027","r2_integrity.py"),rel,label]
    if prev: cmd+=["--prev",prev]
    r=subprocess.run(cmd,capture_output=True,text=True)
    # the script prints 'PASS <path>' or 'FAIL <path>'; also find newest file
    path=None
    for tok in (r.stdout+" "+r.stderr).split():
        if tok.endswith(".json") and ("%s_%s_"%(rel,label)) in tok: path=tok
    if path is None:
        g=sorted(glob.glob(os.path.join(INTD,"%s_%s_*.json"%(rel,label))),key=os.path.getmtime)
        path=g[-1] if g else None
    return path, (r.returncode==0)

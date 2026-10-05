"""Is a stage's output actually a result, or just a file?

Used by run_all.sh. Exits 0 only when the JSON at argv[1] satisfies the
predicate at argv[2]. A stage that ran, wrote, and measured nothing must not
count as done -- that failure has cost this project several runs.
"""
import json, sys

try:
    d = json.load(open(sys.argv[1]))
except Exception as exc:                                          # noqa: BLE001
    print("unparseable: %r" % (exc,), file=sys.stderr)
    sys.exit(1)
try:
    ok = eval(sys.argv[2], {"__builtins__": {"len": len, "all": all, "any": any,
                                             "sum": sum, "isinstance": isinstance}},
              {"d": d})
except Exception as exc:                                          # noqa: BLE001
    print("predicate error: %r" % (exc,), file=sys.stderr)
    sys.exit(1)
sys.exit(0 if ok else 1)

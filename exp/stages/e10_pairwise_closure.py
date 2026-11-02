"""E10 arm D (review r5 Z11; R3 W8; META item 10): pairwise closure mutation with branch coverage of the logbook.

Question. The renderer closure of Home Assistant 2026.7.4 was measured by mutating ONE field at a time (E8 part B,
exp/stages/e8_closure_real.py -> exp/out/e8_closure_real.json: 40 target rows in 22 roles, 45 fields, 1,744 mutations;
27 fields changed the rendered output, exactly the 27 columns the logbook's compiled SQL reads). Could a field matter only
jointly with another, or only on a branch the single mutations never drove the logbook processor down?

Frame and method (drafts/round13/E10_ADDENDUM_R5.md section D). The SAME pristine copy of the lab recorder
(HOMEPROV-P13-exp/e8b_closure/pristine.db, sha256 as registered by E8B), the same release image, the same 40 targets,
render forms, mutation values and commitment code as E8B, on a throwaway hub (e10p-hass, no network, recorder disabled
once started) serving a working copy. Each UNIT applies two mutations (in an order that changes a row's key last),
renders the target's window in the three forms, recomputes the closure, stable-columns and row commitments, and restores
both (checked: rows, renders and commitments equal the baseline). Each single mutation a unit uses is also measured in
this run (cached), so every unit has render(baseline), render(f), render(g), render(f and g).

  W  (exhaustive)  every unordered pair of distinct fields E8B mutated on the same target, each at its PRIMARY variant
                   (E8B's first value for that target and field), on all 40 targets
  V  (sample)      n_V = 1,000 units drawn uniformly (seed) from the same-target pairs in which at least one mutation uses
                   a non-primary variant
  X  (sample)      n_X = 1,000 units drawn uniformly (seed) from cross-row pairs: a field of target A's rows and a field
                   of another target B's rows, B's row inside A's +-300 s window, primary variants, rendered on A's window

Stopping rule (registered): W in a seeded random order, then V, then X, each in its registered order; no stop on any
outcome; the run stops when every unit is done or the measurement time reaches CAP_S (3.0 h), whichever is first, and
reports the units done (a prefix of a random order, so the completed part of V and X stays a random sample). Coverage is
reported, never used to stop.

Outcomes per unit (render equality is byte equality of all three forms):
  undetected_render_change  render(f,g) != render(base) while the STABLE commitment (the deployed scheme) is unchanged
                            -- PRIMARY, predicted 0
  joint_only                render(f,g) != base while render(f) == base and render(g) == base -- predicted 0
  conditional_noncl         a field outside E8B's 27-field closure changes the output once the other changed:
                            render(f,g) != render(g) with render(f) == base and f not in the closure -- predicted 0
  masking                   render(f) != base, render(g) != base, render(f,g) == base (descriptive; irrelevant to a
                            commitment that covers both)
Prediction basis: the logbook's compiled SQL reads exactly the 27 closure columns (E8B static.union), and a column no
statement reads cannot reach the rendered output; the stable scheme commits every states/events column but
last_reported_ts plus the four joined values.

Coverage. A sys.monitoring (PEP 669) tracer on every code object of homeprov's logbook dependency, the package
homeassistant.components.logbook (processor, models, helpers, queries.*): executed / executable lines and taken /
possible branch outcomes (two per conditional jump), cumulative after the baselines, the singles, W, V and X, and the
branch sites never taken. The frontend display rule's four outcomes (user, automation, integration, none) are counted
from the classified renders.

    python3 exp/stages/e10_pairwise_closure.py plan        # offline: units from exp/out/e8_closure_real.json (no Docker)
    python3 exp/stages/e10_pairwise_closure.py up          # e10p-hass on a working copy of the pristine recorder
    python3 exp/stages/e10_pairwise_closure.py run         # the units (resumable), digests before and after
    python3 exp/stages/e10_pairwise_closure.py summarize   # exp/out/e10_pairwise_closure.json (never overwrites)
    python3 exp/stages/e10_pairwise_closure.py down
Inside e10p-hass this file is the custom component e10p_closure (async_setup below); e8_closure_real.py rides along as
its module e8cr (its Inner class renders, commits, applies and restores, unchanged).
"""
from __future__ import annotations

import asyncio
import collections
import dis
import hashlib
import importlib.util
import itertools
import json
import os
import random
import subprocess
import sys
import time

SEED = 20261021
N_V, N_X = 1000, 1000
CAP_S = 3 * 3600.0
CROSS_WINDOW_S = 300.0
STRATA = ("W", "V", "X")
DOMAIN = "e10p_closure"
IO2 = "/config/e10p"
HERE = os.path.dirname(os.path.abspath(__file__))


def _e8():
    """exp/stages/e8_closure_real.py: inside the hub it is this package's module e8cr; on the Mac it is loaded by path."""
    try:
        from . import e8cr as E8                  # noqa: PLC0415  (inside e10p-hass)
        return E8
    except ImportError:
        spec = importlib.util.spec_from_file_location("e8_closure_real", os.path.join(HERE, "e8_closure_real.py"))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m


# ================================================================================================ plan (offline)
def mut_spec(m, keycol):
    """A saved E8B mutation record as the spec E8B's Inner.apply() takes."""
    s = {"id": "%s|%s|%s" % (m["target"], m["field"], m["variant"]), "target": m["target"], "field": m["field"],
         "variant": m["variant"], "table": m["table"], "key_col": keycol[m["table"]], "key": m["key"],
         "col": m["field"].split(".", 1)[1], "new": m["new"]}
    if m.get("also"):
        s["also"] = m["also"]
    return s


def ordered_pair(a, b):
    """The application order of two mutations: on the same row a key-column change goes last; the same row and column
    twice is not a pair (None)."""
    if (a["table"], a["key"], a["col"]) == (b["table"], b["key"], b["col"]):
        return None
    if (a["table"], a["key"]) == (b["table"], b["key"]):
        if a["col"] == a["key_col"]:
            return [b, a]
        if b["col"] == b["key_col"]:
            return [a, b]
    return [a, b]


def make_plan(e8, seed=SEED, n_v=N_V, n_x=N_X):
    """Units of the three strata from E8B's saved result (exp/out/e8_closure_real.json): deterministic from the seed."""
    keycol = {"states": "state_id", "events": "event_id", "states_meta": "metadata_id",
              "state_attributes": "attributes_id", "event_types": "event_type_id", "event_data": "data_id"}
    targets = {t["id"]: t for t in e8["targets"]}
    by_tf = collections.OrderedDict()
    for m in e8["mutations"]:
        by_tf.setdefault((m["target"], m["field"]), []).append(mut_spec(m, keycol))
    prim = {k: v[0] for k, v in by_tf.items()}
    fields_of = collections.defaultdict(list)
    for (t, f) in by_tf:
        fields_of[t].append(f)
    rnd = random.Random(seed)
    W, Vall, Xall = [], [], []
    for t in sorted(fields_of):
        fs = sorted(fields_of[t])
        for f, g in itertools.combinations(fs, 2):
            p = ordered_pair(prim[(t, f)], prim[(t, g)])
            if p:
                W.append({"stratum": "W", "render_target": t, "muts": p})
            for a in by_tf[(t, f)]:
                for b in by_tf[(t, g)]:
                    if a is prim[(t, f)] and b is prim[(t, g)]:
                        continue
                    p = ordered_pair(a, b)
                    if p:
                        Vall.append({"stratum": "V", "render_target": t, "muts": p})
    tids = sorted(targets)
    for ta in tids:
        for tb in tids:
            if ta == tb or abs(float(targets[ta]["ts"]) - float(targets[tb]["ts"])) > CROSS_WINDOW_S:
                continue
            for f in sorted(fields_of[ta]):
                for g in sorted(fields_of[tb]):
                    p = ordered_pair(prim[(ta, f)], prim[(tb, g)])
                    if p:
                        Xall.append({"stratum": "X", "render_target": ta, "muts": p})
    rnd.shuffle(W)
    V = rnd.sample(Vall, min(n_v, len(Vall)))
    X = rnd.sample(Xall, min(n_x, len(Xall)))
    units = W + V + X
    for i, u in enumerate(units):
        u["id"] = "U%05d" % i
    tsel = {}
    for u in units:
        t = targets[u["render_target"]]
        tsel[t["id"]] = {k: t.get(k) for k in ("id", "kind", "role", "key", "ts", "entity", "window", "expect")}
    return {"seed": seed, "n_v": n_v, "n_x": n_x, "cap_s": CAP_S, "cross_window_s": CROSS_WINDOW_S,
            "population": {"W": len(W), "V": len(Vall), "X": len(Xall)},
            "units_per_stratum": {"W": len(W), "V": len(V), "X": len(X)},
            "closure_27": sorted(e8["summary"]["closure_render"]), "targets": tsel, "units": units}


# ================================================================================================ classification
def render_key(r):
    """A unit's or single's render signature: {form: sha256} (equal iff byte-equal in every form)."""
    return tuple(sorted((r or {}).items()))


def classify_unit(rec, base, singles, closure):
    """One measured unit against its target's baseline and its two singles (dicts {"render": {form: sha},
    "commit": {scheme: [digest, n]}}); closure = E8B's 27 fields."""
    f, g = rec["muts"][0], rec["muts"][1]
    Rb, Rf, Rg, Rfg = (render_key(x["render"]) for x in (base, singles[f["id"]], singles[g["id"]], rec))
    st_b, st_fg = base["commit"]["stable"][0], rec["commit"]["stable"][0]
    changed = Rfg != Rb
    out = {"render_changed": changed, "stable_commit_changed": st_fg != st_b,
           "closure_commit_changed": rec["commit"]["closure"][0] != base["commit"]["closure"][0],
           "row_commit_changed": rec["commit"]["row"][0] != base["commit"]["row"][0]}
    out["undetected_render_change"] = changed and not out["stable_commit_changed"]
    out["joint_only"] = changed and Rf == Rb and Rg == Rb
    out["conditional_noncl"] = ((Rf == Rb and Rfg != Rg and f["field"] not in closure)
                                or (Rg == Rb and Rfg != Rf and g["field"] not in closure))
    out["conditional_on_target"] = (Rf == Rb and Rfg != Rg) or (Rg == Rb and Rfg != Rf)
    out["masking"] = Rf != Rb and Rg != Rb and Rfg == Rb
    return out


# ================================================================================================ coverage tracer
_BRANCH_OPS = {"POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE", "POP_JUMP_IF_NONE", "POP_JUMP_IF_NOT_NONE",
               "POP_JUMP_FORWARD_IF_FALSE", "POP_JUMP_FORWARD_IF_TRUE", "POP_JUMP_FORWARD_IF_NONE",
               "POP_JUMP_FORWARD_IF_NOT_NONE", "POP_JUMP_BACKWARD_IF_FALSE", "POP_JUMP_BACKWARD_IF_TRUE",
               "POP_JUMP_BACKWARD_IF_NONE", "POP_JUMP_BACKWARD_IF_NOT_NONE", "FOR_ITER"}


def code_objects(objs):
    """Every code object reachable from functions, methods, properties and classes in `objs` (and their nested code
    constants): the live objects, so per-code monitoring events apply to the running code."""
    import types                                                   # noqa: PLC0415
    seen, out, todo = set(), [], list(objs)
    while todo:
        o = todo.pop()
        if o is None or id(o) in seen:
            continue
        seen.add(id(o))
        if isinstance(o, types.CodeType):
            out.append(o)
            todo.extend(c for c in o.co_consts if isinstance(c, types.CodeType))
        elif isinstance(o, type):
            todo.extend(vars(o).values())
        elif isinstance(o, (staticmethod, classmethod)):
            todo.append(o.__func__)
        elif isinstance(o, property):
            todo.extend((o.fget, o.fset, o.fdel))
        elif isinstance(o, types.FunctionType):
            todo.append(o.__code__)
            todo.append(getattr(o, "__wrapped__", None))
    return out


class BranchTracer:
    """Line and branch-outcome coverage of chosen code objects with sys.monitoring (Python 3.12+), local events only,
    each location disabled once fully seen (a line at its first execution, a branch site once both outcomes occur)."""

    def __init__(self, name="e10p"):
        self.name = name
        self.tool = None
        self.codes = []
        self.lines_hit = collections.defaultdict(set)          # file -> {line}
        self.branch_hit = collections.defaultdict(set)         # (file, qualname, offset) -> {destination}
        self.marks = []

    def start(self, codes):
        mon = sys.monitoring
        for tid in (mon.COVERAGE_ID, 4, 5):
            if mon.get_tool(tid) is None:
                self.tool = tid
                break
        if self.tool is None:
            raise RuntimeError("no free sys.monitoring tool id")
        mon.use_tool_id(self.tool, self.name)
        ev = mon.events
        br = ev.BRANCH_LEFT | ev.BRANCH_RIGHT if hasattr(ev, "BRANCH_LEFT") else ev.BRANCH
        mon.register_callback(self.tool, ev.LINE, self._line)
        for e in ((ev.BRANCH_LEFT, ev.BRANCH_RIGHT) if hasattr(ev, "BRANCH_LEFT") else (ev.BRANCH,)):
            mon.register_callback(self.tool, e, self._branch)
        self.codes = list(codes)
        for c in self.codes:
            mon.set_local_events(self.tool, c, ev.LINE | br)

    def _line(self, code, line):
        self.lines_hit[code.co_filename].add(line)
        return sys.monitoring.DISABLE

    def _branch(self, code, src, dst):
        k = (code.co_filename, code.co_qualname, src)
        s = self.branch_hit[k]
        s.add(dst)
        return sys.monitoring.DISABLE if len(s) >= 2 else None

    def stop(self):
        if self.tool is not None:
            mon = sys.monitoring
            for c in self.codes:
                try:
                    mon.set_local_events(self.tool, c, 0)
                except ValueError:
                    pass
            mon.free_tool_id(self.tool)
            self.tool = None

    @staticmethod
    def static(codes):
        lines, sites = collections.defaultdict(set), collections.defaultdict(set)
        for c in codes:
            lines[c.co_filename] |= {ln for _a, _b, ln in c.co_lines() if ln is not None and ln != c.co_firstlineno}
            for ins in dis.get_instructions(c):
                if ins.opname in _BRANCH_OPS:
                    sites[c.co_filename].add((c.co_qualname, ins.offset, ins.positions.lineno if ins.positions else None))
        return lines, sites

    def mark(self, label):
        """A cumulative snapshot: per file, lines executed / executable, branch outcomes taken / possible."""
        lines, sites = self.static(self.codes)
        rep = {}
        for fn in sorted(set(lines) | set(sites)):
            taken = sum(len(v) for (f, _q, _o), v in self.branch_hit.items() if f == fn)
            rep[fn] = {"lines": [len(self.lines_hit.get(fn, set()) & lines[fn]), len(lines[fn])],
                       "branch_outcomes": [min(taken, 2 * len(sites[fn])), 2 * len(sites[fn])]}
        self.marks.append({"label": label, "t": time.time(), "files": rep,
                           "total": {"lines": [sum(v["lines"][0] for v in rep.values()), sum(v["lines"][1] for v in rep.values())],
                                     "branch_outcomes": [sum(v["branch_outcomes"][0] for v in rep.values()),
                                                         sum(v["branch_outcomes"][1] for v in rep.values())]}})
        return self.marks[-1]

    def never_taken(self):
        lines, sites = self.static(self.codes)
        out = []
        for fn, ss in sites.items():
            for q, off, ln in sorted(ss, key=lambda x: (x[0], x[1])):
                n = len(self.branch_hit.get((fn, q, off), set()))
                if n < 2:
                    out.append({"file": fn.split("/homeassistant/")[-1], "function": q, "line": ln, "outcomes_seen": n})
        return out


def logbook_codes():
    """The live code objects of every loaded module of homeassistant.components.logbook (inside the hub)."""
    mods = [m for n, m in sorted(sys.modules.items()) if n.startswith("homeassistant.components.logbook") and m]
    return code_objects([v for m in mods for v in vars(m).values()
                         if getattr(v, "__module__", "").startswith("homeassistant.components.logbook")])


# ================================================================================================ inside the hub
def make_inner(E8):
    class PairInner(E8.Inner):
        def apply_pair(self, muts):
            done = []
            try:
                for m in muts:
                    origs, cur = self.apply(m)
                    done.append((m, origs, cur))
            except Exception:
                for m, origs, cur in reversed(done):
                    self.restore(m, origs, cur)
                raise
            return done

        def restore_pair(self, done):
            for m, origs, cur in reversed(done):
                self.restore(m, origs, cur)

        async def measure(self, tgt, muts, start, end, lo, hi, base, exp):
            """Apply the mutations, render and commit, restore, check the restore. base: {form: (bytes, rows)} plus
            "_commit"."""
            forms = [f for f in base if f != "_commit"]
            before = [await self.job(self.row, m["table"], m["key_col"], m["key"]) for m in muts]
            done = await self.job(self.apply_pair, muts)
            try:
                after = await self.render_all(tgt, start, end)
                cm = await self.job(self.commit, lo, hi)
            finally:
                await self.job(self.restore_pair, done)
            rest = await self.render_all(tgt, start, end)
            rc = await self.job(self.commit, lo, hi)
            now = [await self.job(self.row, m["table"], m["key_col"], m["key"]) for m in muts]
            return {"render": {f: hashlib.sha256(after[f][0]).hexdigest() for f in forms if f in after},
                    "effect": {f: E8.compare(base[f][1], after[f][1], base[f][0], after[f][0], exp[f])
                               for f in forms if f in after},
                    "commit": cm, "restore": {"db_equal": now == before,
                                              "render_equal": all(f in rest and rest[f][0] == base[f][0] for f in forms),
                                              "commit_equal": rc == base["_commit"]}}

        def _context(self, tgt):
            from datetime import datetime, timezone                      # noqa: PLC0415
            from homeassistant.components.recorder.models import process_timestamp_to_utc_isoformat  # noqa: PLC0415
            start = datetime.fromtimestamp(tgt["window"][0], timezone.utc)
            end = datetime.fromtimestamp(tgt["window"][1], timezone.utc)
            lo, hi = tgt["window"][0] - E8.COMMIT_MARGIN, tgt["window"][1] + E8.COMMIT_MARGIN
            exp = {}
            for f in E8.FORMS:
                e = dict(tgt["expect"]) if tgt.get("expect") else None
                if e is not None and f == "rest_entity":
                    e["when"] = process_timestamp_to_utc_isoformat(datetime.fromtimestamp(e["when"], timezone.utc))
                exp[f] = e
            return start, end, lo, hi, exp

        async def run_pairs(self, plan, out_path, tracer):
            """Phase 0 the baselines of every render target, phase 1 every single mutation a unit uses (on its render
            target), then the units stratum by stratum in the registered order, until done or the time cap (CAP_S,
            counted from the start of phase 0). Coverage is marked after each phase and stratum."""
            done_ids = set()
            if os.path.exists(out_path):
                for line in open(out_path):
                    done_ids.add(json.loads(line).get("id"))
            t_begin, n, stopped = time.time(), 0, None
            bases = {}
            mark = (lambda lab: tracer.mark(lab)) if tracer is not None else (lambda lab: None)   # noqa: E731
            with open(out_path, "a") as fh:
                for tid in sorted({u["render_target"] for u in plan["units"]}):
                    tgt = plan["targets"][tid]
                    start, end, lo, hi, _exp = self._context(tgt)
                    await self.render_all(tgt, start, end)
                    b = await self.render_all(tgt, start, end)
                    b2 = await self.render_all(tgt, start, end)
                    b["_commit"] = await self.job(self.commit, lo, hi)
                    bases[tid] = b
                    fh.write(json.dumps({"kind": "baseline", "target": tid,
                                         "render": {f: hashlib.sha256(b[f][0]).hexdigest() for f in b if f != "_commit"},
                                         "commit": b["_commit"],
                                         "determinism_equal": all(b2[f][0] == b[f][0] for f in b2)}) + "\n")
                mark("after_baselines")
                need = collections.OrderedDict()
                for u in plan["units"]:
                    for m in u["muts"]:
                        need.setdefault((u["render_target"], m["id"]), m)
                for (tid, _mid), m in need.items():
                    tgt = plan["targets"][tid]
                    start, end, lo, hi, exp = self._context(tgt)
                    try:
                        r = await self.measure(tgt, [m], start, end, lo, hi, bases[tid], exp)
                    except Exception as exc:                      # noqa: BLE001
                        r = {"apply_error": repr(exc)[:300]}
                    fh.write(json.dumps({"kind": "single", "target": tid, "mut": m["id"], **r}, default=str) + "\n")
                fh.flush()
                mark("after_singles")
                last = None
                for u in plan["units"]:
                    if u["id"] in done_ids:
                        continue
                    if time.time() - t_begin > plan["cap_s"]:
                        stopped = "time cap"
                        break
                    if u["stratum"] != last:
                        if last is not None:
                            mark("after_%s" % last)
                        last = u["stratum"]
                    tgt = plan["targets"][u["render_target"]]
                    start, end, lo, hi, exp = self._context(tgt)
                    rec = {"kind": "unit", "id": u["id"], "stratum": u["stratum"], "target": tgt["id"],
                           "muts": [m["id"] for m in u["muts"]]}
                    try:
                        rec.update(await self.measure(tgt, u["muts"], start, end, lo, hi, bases[tgt["id"]], exp))
                    except Exception as exc:                      # noqa: BLE001
                        rec["apply_error"] = repr(exc)[:300]
                    fh.write(json.dumps(rec, default=str) + "\n")
                    fh.flush()
                    n += 1
                if last is not None:
                    mark("after_%s" % last)
            return {"units_run": n, "stopped": stopped or "all units done", "seconds": round(time.time() - t_begin, 1)}

    return PairInner


async def async_setup(hass, config):
    """Custom-component entry point inside e10p-hass."""
    from homeassistant.const import EVENT_HOMEASSISTANT_STARTED      # noqa: PLC0415
    from homeassistant.components.recorder import get_instance       # noqa: PLC0415
    E8 = _e8()
    inner = make_inner(E8)(hass)
    os.makedirs(IO2, exist_ok=True)
    state = {"tracer": None}

    async def _started(_ev=None):
        await hass.services.async_call("recorder", "disable", {}, blocking=True)
        await get_instance(hass).async_block_till_done()
        with open(os.path.join(IO2, "ready.json"), "w") as fh:
            json.dump({"ready_at": time.time(), "recorder_enabled": get_instance(hass).enabled}, fh)

    hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STARTED, _started)

    async def cmd(c):
        op = c["op"]
        if op in ("info", "digest"):
            return await inner.cmd(c)
        if op == "run_pairs":
            plan = json.load(open(os.path.join(IO2, "plan_pairs.json")))
            os.makedirs(os.path.join(IO2, "out"), exist_ok=True)
            tr = BranchTracer()
            tr.start(logbook_codes())
            state["tracer"] = tr
            tr.mark("start")
            try:
                r = await inner.run_pairs(plan, os.path.join(IO2, "out", "pairs_raw.jsonl"), tr)
            finally:
                tr.mark("end")
                cov = {"marks": tr.marks, "never_taken": tr.never_taken(), "n_code_objects": len(tr.codes),
                       "python": sys.version.split()[0]}
                tr.stop()
                with open(os.path.join(IO2, "out", "coverage.json"), "w") as fh:
                    json.dump(cov, fh, indent=1)
            return r
        return {"err": "unknown op %r" % op}

    async def _loop():
        while True:
            p = os.path.join(IO2, "cmd.json")
            if os.path.exists(p):
                try:
                    c = json.load(open(p))
                except ValueError:
                    await asyncio.sleep(1)
                    continue
                os.remove(p)
                try:
                    out = await cmd(c)
                except Exception as exc:                          # noqa: BLE001
                    import traceback                              # noqa: PLC0415
                    out = {"err": repr(exc), "tb": traceback.format_exc()}
                tmp = os.path.join(IO2, "ack.tmp")
                with open(tmp, "w") as fh:
                    json.dump({"op": c.get("op"), "tag": c.get("tag"), "result": out}, fh, default=str)
                os.replace(tmp, os.path.join(IO2, "ack_%s.json" % c.get("tag", c.get("op"))))
            await asyncio.sleep(1)

    hass.async_create_background_task(_loop(), "e10p_closure_loop")
    return True


# ================================================================================================ host side
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
OUT = os.path.join(REPO, "exp", "out")
E8_JSON = os.path.join(OUT, "e8_closure_real.json")
DST = os.path.join(OUT, "e10_pairwise_closure.json")
DATA = "<research-dir>/HOMEPROV-P13-exp/e10/pairwise"
PRISTINE = "<research-dir>/HOMEPROV-P13-exp/e8b_closure/pristine.db"
CFG = os.path.join(DATA, "config")
IMAGE = "homeassistant/home-assistant:2026.7.4"
CONTAINER, VOLUME = "e10p-hass", "e10p-db"
NOT_BEFORE = 1792425660                         # 2026-10-19T16:01:00Z: E9 owns Docker until then


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def smoke_plan(p, n_w=100, n_v=20, n_x=20, cap_s=900.0):
    """The smoke's plan: a prefix of each stratum of the registered plan and a 15-min cap (smokes are not results)."""
    keep, c = [], collections.Counter()
    lim = {"W": n_w, "V": n_v, "X": n_x}
    for u in p["units"]:
        if c[u["stratum"]] < lim[u["stratum"]]:
            keep.append(u)
            c[u["stratum"]] += 1
    q = dict(p, units=keep, cap_s=cap_s, smoke=True, units_per_stratum={s: c.get(s, 0) for s in STRATA})
    q["targets"] = {t: v for t, v in p["targets"].items() if any(u["render_target"] == t for u in keep)}
    return q


def plan():
    e8 = json.load(open(E8_JSON))
    p = make_plan(e8)
    if "--smoke" in sys.argv:
        p = smoke_plan(p)
    p["pristine_sha256_registered"] = e8["plan"]["pristine_sha256"]
    p["source"] = {"file": "exp/out/e8_closure_real.json", "sha256": sha(E8_JSON)}
    os.makedirs(os.path.join(CFG, "e10p"), exist_ok=True)
    path = os.path.join(CFG, "e10p", "plan_pairs.json")
    with open(path, "w") as fh:
        json.dump(p, fh)
    print("plan", path, p["units_per_stratum"], "population", p["population"])


def _refuse_early():
    if time.time() < NOT_BEFORE:
        raise SystemExit("REFUSING: before 2026-10-19T16:01:00Z (E9 owns Docker on this Mac)")


def up():
    import shutil                                                      # noqa: PLC0415
    _refuse_early()
    E8 = _e8()
    if sha(PRISTINE) != json.load(open(E8_JSON))["plan"]["pristine_sha256"]:
        raise SystemExit("the pristine copy differs from E8B's")
    if sh(["docker", "ps", "-a", "--format", "{{.Names}}"]).stdout.split().count(CONTAINER):
        raise SystemExit("%s exists" % CONTAINER)
    cc = os.path.join(CFG, "custom_components", DOMAIN)
    os.makedirs(cc, exist_ok=True)
    os.makedirs(os.path.join(CFG, "e8b"), exist_ok=True)
    shutil.copy(os.path.abspath(__file__), os.path.join(cc, "__init__.py"))
    shutil.copy(os.path.join(HERE, "e8_closure_real.py"), os.path.join(cc, "e8cr.py"))
    json.dump({"domain": DOMAIN, "name": "E10 pairwise closure", "version": "1.0.0", "documentation": "",
               "codeowners": [], "dependencies": ["recorder", "logbook"], "iot_class": "local_polling",
               "requirements": []}, open(os.path.join(cc, "manifest.json"), "w"))
    shutil.copy(os.path.join(REPO, "testbed", "real", "ha-config", "automations.yaml"), os.path.join(CFG, "automations.yaml"))
    bp = os.path.join(CFG, "blueprints", "automation", "homeassistant")
    os.makedirs(bp, exist_ok=True)
    r = sh(["docker", "run", "--rm", "--name", "e10p-prep", "--network", "none", "--entrypoint", "cat", IMAGE,
            "/usr/src/homeassistant/homeassistant/components/automation/blueprints/motion_light.yaml"])
    open(os.path.join(bp, "motion_light.yaml"), "w").write(r.stdout)
    shutil.copy(os.path.join(REPO, "monitor", "monitor.py"), os.path.join(CFG, "e8b", "monitor_snapshot.py"))
    open(os.path.join(CFG, "configuration.yaml"), "w").write(E8.CONFIG_YAML.replace("e8b_closure:", DOMAIN + ":"))
    for f in ("ready.json", "cmd.json"):
        if os.path.exists(os.path.join(CFG, "e10p", f)):
            os.remove(os.path.join(CFG, "e10p", f))
    sh(["docker", "volume", "create", VOLUME])
    r = sh(["docker", "run", "--rm", "--name", "e10p-prep", "--network", "none", "--entrypoint", "sh", "-v",
            "%s:/e8bdb" % VOLUME, "-v", "%s:/src:ro" % os.path.dirname(PRISTINE), IMAGE, "-c",
            "cp /src/pristine.db /e8bdb/work.db && sha256sum /e8bdb/work.db"])
    if r.returncode or sha(PRISTINE) not in r.stdout:
        raise SystemExit("copy into volume failed: %s %s" % (r.stdout, r.stderr))
    r = sh(["docker", "run", "-d", "--name", CONTAINER, "--network", "none", "-e", "TZ=UTC", "-v", "%s:/config" % CFG,
            "-v", "%s:/e8bdb" % VOLUME, IMAGE])
    if r.returncode:
        raise SystemExit(r.stderr)
    t0 = time.time()
    while not os.path.exists(os.path.join(CFG, "e10p", "ready.json")):
        if time.time() - t0 > 600:
            raise SystemExit("hub not ready after 600 s")
        time.sleep(3)
    print("ready", round(time.time() - t0, 1), "s")


def send(op, tag, timeout=7200, **kw):
    ack = os.path.join(CFG, "e10p", "ack_%s.json" % tag)
    if os.path.exists(ack):
        os.remove(ack)
    tmp = os.path.join(CFG, "e10p", "cmd.tmp")
    json.dump({"op": op, "tag": tag, **kw}, open(tmp, "w"))
    os.replace(tmp, os.path.join(CFG, "e10p", "cmd.json"))
    t0 = time.time()
    while not os.path.exists(ack):
        if time.time() - t0 > timeout:
            raise SystemExit("timeout waiting for %s" % tag)
        time.sleep(2)
    return json.load(open(ack))["result"]


def run():
    _refuse_early()
    E8 = _e8()
    p = json.load(open(os.path.join(CFG, "e10p", "plan_pairs.json")))
    info = send("info", "info")
    json.dump(info, open(os.path.join(CFG, "e10p", "out_info.json"), "w"), indent=1)
    if info.get("recorder_enabled"):
        raise SystemExit("recorder still enabled")
    wm = json.load(open(E8_JSON))["plan"]["watermarks"]
    pristine = E8.table_digest(PRISTINE, wm)
    pre = send("digest", "digest_pre", watermarks=wm)
    if not all(pre[t]["sha256"] == pristine[t]["sha256"] for t in E8.TABLES):
        raise SystemExit("the hub changed the copy before the run")
    r = send("run_pairs", "run_pairs", timeout=int(p["cap_s"]) + 3 * 3600)
    post = send("digest", "digest_post", watermarks=wm)
    json.dump({"run": r, "pre_equal": True, "post_equal": {t: post[t]["sha256"] == pristine[t]["sha256"] for t in E8.TABLES}},
              open(os.path.join(CFG, "e10p", "out_run.json"), "w"), indent=1)
    print("run", r)


def summarize_records(plan_doc, raw_lines):
    """The result document's core from the plan and the raw JSON lines (pure: tested offline)."""
    base, singles_by_target, units = {}, collections.defaultdict(dict), []
    for line in raw_lines:
        d = json.loads(line)
        if d["kind"] == "baseline":
            base[d["target"]] = d
        elif d["kind"] == "single":
            singles_by_target[d["target"]][d["mut"]] = d
        else:
            units.append(d)
    closure = set(plan_doc["closure_27"])
    plan_units = {u["id"]: u for u in plan_doc["units"]}
    res = {s: collections.Counter() for s in STRATA}
    examples = collections.defaultdict(list)
    restores_bad, errors = [], []
    display = collections.Counter()
    for d in units:
        s = d["stratum"]
        res[s]["done"] += 1
        if d.get("apply_error"):
            res[s]["apply_error"] += 1
            errors.append({"id": d["id"], "err": d["apply_error"]})
            continue
        if not all((d.get("restore") or {}).get(k) for k in ("db_equal", "render_equal", "commit_equal")):
            restores_bad.append(d["id"])
        u = plan_units[d["id"]]
        b = base[d["target"]]
        sg = {m["id"]: singles_by_target[d["target"]].get(m["id"]) for m in u["muts"]}
        if any(x is None or x.get("apply_error") for x in sg.values()):
            res[s]["single_missing_or_error"] += 1
            continue
        c = classify_unit({"muts": u["muts"], "render": d["render"], "commit": d["commit"]},
                          {"render": b["render"], "commit": b["commit"]},
                          {k: {"render": x["render"], "commit": x["commit"]} for k, x in sg.items()}, closure)
        for k, v in c.items():
            if v:
                res[s][k] += 1
                if k in ("undetected_render_change", "joint_only", "conditional_noncl", "masking") and len(examples[k]) < 20:
                    examples[k].append({"id": d["id"], "fields": [m["field"] for m in u["muts"]], "target": d["target"]})
        for eff in (d.get("effect") or {}).values():
            t = (eff or {}).get("target") or {}
            for k in ("display_admin_before", "display_admin_after"):
                v = t.get(k)
                if v:
                    display[v.split(":")[0]] += 1
    per = {s: {"units_planned": plan_doc["units_per_stratum"][s], "population": plan_doc["population"][s],
               **dict(res[s])} for s in STRATA}
    n_noevent = {s: per[s].get("done", 0) - per[s].get("apply_error", 0) for s in STRATA}
    bound = {s: (round(1 - 0.05 ** (1.0 / n_noevent[s]), 6) if n_noevent[s] and not per[s].get("undetected_render_change")
                 else None) for s in STRATA}
    return {"per_stratum": per, "one_sided_95_upper_bound_undetected_rate_if_zero": bound,
            "examples": dict(examples), "restore_failures": restores_bad, "apply_errors": errors[:50],
            "display_rule_outcomes_seen": dict(display),
            "predictions": {"undetected_render_change": 0, "joint_only": 0, "conditional_noncl": 0}}


def summarize():
    p = json.load(open(os.path.join(CFG, "e10p", "plan_pairs.json")))
    dst = os.path.join(DATA, "smoke_summary.json") if p.get("smoke") else DST
    if os.path.exists(dst):
        raise SystemExit("REFUSING: %s exists" % dst)
    raw = open(os.path.join(CFG, "e10p", "out", "pairs_raw.jsonl")).read().splitlines()
    core = summarize_records(p, raw)
    cov = json.load(open(os.path.join(CFG, "e10p", "out", "coverage.json")))
    runinfo = json.load(open(os.path.join(CFG, "e10p", "out_run.json")))
    doc = {"experiment": "E10 arm D: pairwise closure mutation with branch coverage of the logbook (Home Assistant "
                         "2026.7.4, a copy of the lab recorder)", "plan": {k: p[k] for k in (
                             "seed", "n_v", "n_x", "cap_s", "cross_window_s", "population", "units_per_stratum")},
           "source": p.get("source"), "pristine_sha256": p.get("pristine_sha256_registered"), "run": runinfo,
           **core, "coverage": {"marks": cov["marks"], "never_taken_branch_sites": cov["never_taken"][:400],
                                "n_never_taken": len(cov["never_taken"]), "python": cov.get("python")},
           "script_sha256": sha(os.path.abspath(__file__)), "smoke": bool(p.get("smoke")),
           "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    with open(dst, "x") as fh:
        json.dump(doc, fh, indent=1, default=str)
    print("wrote", dst)


def down():
    sh(["docker", "rm", "-f", CONTAINER])
    sh(["docker", "rm", "-f", "e10p-prep"])
    sh(["docker", "volume", "rm", VOLUME])


if __name__ == "__main__":
    {"plan": plan, "up": up, "run": run, "summarize": summarize, "down": down}[sys.argv[1]]()

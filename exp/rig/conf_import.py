"""Bridge so rig modules can read the frozen catalog without a package install."""
import importlib.util, os
_p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "conf", "catalog.py")
_s = importlib.util.spec_from_file_location("homeprov_catalog", _p)
_m = importlib.util.module_from_spec(_s); _s.loader.exec_module(_m)
FORGERY_CATALOG = _m.FORGERY_CATALOG
SEVERITY = _m.SEVERITY
BENIGN_CATALOG = _m.BENIGN_CATALOG
SEMANTIC_INVARIANTS = _m.SEMANTIC_INVARIANTS
THRESHOLDS = _m.THRESHOLDS
BASELINES = _m.BASELINES
ABLATIONS = _m.ABLATIONS
CONTRASTS = _m.CONTRASTS
OBSERVABILITY = _m.OBSERVABILITY
FROZEN = _m.FROZEN

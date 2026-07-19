import hashlib, json, random, sys, unittest
from pathlib import Path
import yaml
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/"lib"))
from sippycup.envelope import compile_envelope_plan, simulate_envelope_plan
from sippycup.envelope_analysis import analyze_degradation
from sippycup.envelope_recovery import prove_recovery
RAW=(ROOT/"examples/ferivox-envelope.yaml").read_bytes()
PLAN=compile_envelope_plan(yaml.safe_load(RAW),hashlib.sha256(RAW).hexdigest())
P=json.loads((ROOT/"config/envelope-policy.json").read_text()); POLICY={k:P[k] for k in ("staleAfterMs","baselineSamples","metrics")}
EXPECT={"sip":200,"media":"bidirectional"}
ART={s["level"]:{"capture":f"level-{s['level']}.pcap","assertions":f"level-{s['level']}.json"} for s in PLAN["steps"]}
def trace(values, missing=None):
 out=[]
 for i,v in enumerate(values):
  fact={"state":"known","value":v,"source":"sipp"}
  if missing==i: fact={"state":"missing","source":"health","detail":"adapter lost"}
  out.append({"level":i+1,"atMs":i*1000,"metrics":{"call.setupP95Ms":fact,"call.timeoutRatePercent":{"state":"known","value":0,"source":"sipp"}}})
 return out
def recover(a, canaries, reason=None):
 return prove_recovery(PLAN,a,expectations=EXPECT,baseline={"expectations":EXPECT,"passed":True},canaries=[{"expectations":EXPECT,"passed":x} for x in canaries],trigger_at_seconds=100,teardown_seconds=10,canary_interval_seconds=20,level_artifacts={k:ART[k] for k in [d["level"] for d in a["decisions"]]},stop_reason=reason)
class CapacityExitGate(unittest.TestCase):
 def test_healthy_endpoint_stops_exactly_at_authorized_ceiling(self):
  sim=simulate_envelope_plan(PLAN); a=analyze_degradation(PLAN,trace([100]*8),POLICY)
  self.assertEqual(sim["testedLevels"][-1],8); self.assertEqual(a["outcome"],"censored")
  self.assertEqual(a["testedKneeInterval"]["lowerTestedHealthy"],8); self.assertIsNone(a["capacityClaim"])
  self.assertLessEqual(sim["consumedWorstCase"]["calls"],PLAN["authorization"]["hardMaxima"]["totalCalls"])
 def test_gradual_degradation_backs_off_before_hard_maximum(self):
  a=analyze_degradation(PLAN,trace([100,105,205,215]),POLICY)
  self.assertEqual((a["outcome"],a["trigger"]["level"]),("degraded",4)); self.assertLess(4,8)
  r=recover(a,[False,True]); self.assertEqual(r["outcome"],"recovered_after_load_failure")
 def test_abrupt_health_loss_and_sigint_stop_immediately(self):
  abrupt=analyze_degradation(PLAN,trace([100,600]),POLICY); self.assertEqual(abrupt["outcome"],"hard_stop")
  lost=analyze_degradation(PLAN,trace([100],missing=0),POLICY); self.assertEqual(lost["trigger"]["action"],"stop")
  for reason in ("health_adapter_failure","sigint"):
   self.assertEqual(recover(lost,[],reason)["events"][0]["reason"],reason)
 def test_slow_and_never_recovery_timing(self):
  a=analyze_degradation(PLAN,trace([100,600]),POLICY)
  slow=recover(a,[False,False,True]); self.assertEqual(slow["recoveryTimeSeconds"],80)
  never=recover(a,[False]*20); self.assertEqual(never["outcome"],"failed_to_recover")
  self.assertLessEqual(never["deadlines"]["recoveryEnd"],PLAN["authorization"]["hardMaxima"]["durationSeconds"])
 def test_seeded_runs_have_identical_tested_intervals(self):
  def run():
   rng=random.Random(20260718); vals=[100+rng.randint(-5,5),105+rng.randint(-5,5),210+rng.randint(-5,5),220+rng.randint(-5,5)]
   return analyze_degradation(PLAN,trace(vals),POLICY)["testedKneeInterval"]
  self.assertEqual(run(),run())
 def test_policy_and_trace_contract_is_owner_reviewable(self):
  self.assertTrue(P["ownerApprovalRequired"]); self.assertTrue(ART)
  for level,item in ART.items(): self.assertEqual(set(item),{"capture","assertions"})

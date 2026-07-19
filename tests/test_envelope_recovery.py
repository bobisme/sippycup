import hashlib, sys, unittest
from pathlib import Path
import yaml
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/"lib"))
from sippycup.envelope import compile_envelope_plan, EnvelopeError
from sippycup.envelope_recovery import prove_recovery
RAW=(ROOT/"examples/ferivox-envelope.yaml").read_bytes()
PLAN=compile_envelope_plan(yaml.safe_load(RAW),hashlib.sha256(RAW).hexdigest())
EXPECT={"sip":200,"media":"bidirectional"}
def analysis(outcome="degraded"):
 return {"outcome":outcome,"testedKneeInterval":{"lowerTestedHealthy":2,"upperTestedDegraded":3,"censoredByTestedCeiling":False},"trigger":{"level":3},"policy":{"p":1},"decisions":[{"level":1},{"level":2},{"level":3}]}
ART={i:{"capture":f"{i}.pcap","assertions":f"{i}.json"} for i in (1,2,3)}
class Tests(unittest.TestCase):
 def test_recovery_and_failure_are_distinct(self):
  kw=dict(plan=PLAN,analysis=analysis(),expectations=EXPECT,baseline={"expectations":EXPECT,"passed":True},trigger_at_seconds=100,teardown_seconds=10,canary_interval_seconds=20,level_artifacts=ART)
  ok=prove_recovery(canaries=[{"expectations":EXPECT,"passed":False},{"expectations":EXPECT,"passed":True}],**kw)
  self.assertEqual((ok["outcome"],ok["recoveryTimeSeconds"]),("recovered_after_load_failure",60))
  bad=prove_recovery(canaries=[{"expectations":EXPECT,"passed":False}]*10,**kw)
  self.assertEqual(bad["outcome"],"failed_to_recover")
 def test_sigint_adapter_and_global_deadline_share_safe_backoff(self):
  for reason in ("sigint","health_adapter_failure"):
   r=prove_recovery(PLAN,analysis("unknown"),expectations=EXPECT,baseline={"expectations":EXPECT},canaries=[],trigger_at_seconds=590,teardown_seconds=99,canary_interval_seconds=5,level_artifacts=ART,stop_reason=reason)
   self.assertEqual(r["deadlines"]["teardownEnd"],600); self.assertEqual(r["events"][0]["reason"],reason)
 def test_expectations_and_artifacts_fail_closed(self):
  with self.assertRaises(EnvelopeError): prove_recovery(PLAN,analysis(),expectations=EXPECT,baseline={"expectations":{}},canaries=[],trigger_at_seconds=1,teardown_seconds=1,canary_interval_seconds=1,level_artifacts=ART)
  with self.assertRaises(EnvelopeError): prove_recovery(PLAN,analysis(),expectations=EXPECT,baseline={"expectations":EXPECT},canaries=[],trigger_at_seconds=1,teardown_seconds=1,canary_interval_seconds=1,level_artifacts={})
 def test_censored_report_never_claims_capacity(self):
  a=analysis("censored"); a["trigger"]=None
  r=prove_recovery(PLAN,a,expectations=EXPECT,baseline={"expectations":EXPECT},canaries=[{"expectations":EXPECT,"passed":True}],trigger_at_seconds=100,teardown_seconds=0,canary_interval_seconds=10,level_artifacts=ART)
  self.assertTrue(r["authorizationCensored"]); self.assertIsNone(r["capacityClaim"])

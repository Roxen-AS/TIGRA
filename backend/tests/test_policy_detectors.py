"""Unit tests for policy routing/rules and pattern detectors (stdlib unittest; no data files needed).

  cd backend && python -m unittest discover -s tests -v
"""
import unittest

from tigra import detectors as D
from tigra.policy import PolicyContext, final_plan, initial_plan, route, sar_required, settled


def txn(i, ts, amt, channel="online", **kw):
    base = {"txn_id": i, "ts": ts, "amt": amt, "channel": channel, "card_id": "C00001-K1", "product": "C",
            "device_id": None, "device_status": None, "proxy": None, "p_email": None, "r_email": None, "addr1": None,
            "device_profile": None}
    base.update(kw)
    return base


def ctx(**kw):
    base = dict(trigger="risk_score", p=0.5, n_fraud_groups=1, pattern="card_not_present_fraud", exposure=100.0, flagged_amt=100.0)
    base.update(kw)
    return PolicyContext(**base)


def names(plan):
    return [a["action"] for a in plan.to_list()]


class RoutingTests(unittest.TestCase):
    def test_routes_follow_section_2(self):
        self.assertEqual(route("VERIFY_WITH_CUSTOMER", 10), "auto")
        self.assertEqual(route("DECLINE_TRANSACTION", 10), "L1")
        self.assertEqual(route("BLOCK_CARD", 2500), "L1")
        self.assertEqual(route("BLOCK_CARD", 2500.01), "L2")
        self.assertEqual(route("FILE_REPORT", 1), "L2")
        self.assertEqual(route("BLOCK_ALL_CARDS", 1), "L2")

    def test_stopping_rule_needs_two_independent_groups(self):
        self.assertTrue(settled(0.9, 2))
        self.assertFalse(settled(0.9, 1))
        self.assertTrue(settled(0.1, 2))
        self.assertFalse(settled(0.5, 5))


class RuleTests(unittest.TestCase):
    def test_r1_weak_signal_verifies_before_block(self):
        plan = initial_plan(ctx(p=0.45), "customer_validation")
        self.assertIn("VERIFY_WITH_CUSTOMER", names(plan))
        self.assertIn("CREATE_CASE", names(plan))          # 3a: evidence requested -> case
        self.assertNotIn("BLOCK_CARD", names(plan))

    def test_r2_denial_blocks_and_reports_over_1000(self):
        c = ctx(p=0.9, exposure=1500)
        fin = final_plan(c, "deny", initial_plan(c, "customer_validation"))
        self.assertEqual(names(fin)[:2], ["BLOCK_CARD", "CREATE_CASE"])
        self.assertIn("FILE_REPORT", names(fin))

    def test_r2_small_exposure_is_case_only(self):
        c = ctx(p=0.9, exposure=120)
        fin = final_plan(c, "deny", initial_plan(c, "customer_validation"))
        self.assertNotIn("FILE_REPORT", names(fin))

    def test_r3_confirmation_closes(self):
        c = ctx(p=0.3)
        self.assertEqual(names(final_plan(c, "confirm", initial_plan(c, "customer_validation"))), ["ALLOW_TRANSACTION", "CLOSE_NO_FRAUD"])

    def test_r4_no_reply_escalates_over_500(self):
        c = ctx(p=0.5, exposure=800)
        fin = names(final_plan(c, "no_reply", initial_plan(c, "customer_validation")))
        self.assertIn("MONITOR_CARD", fin)
        self.assertIn("DECLINE_TRANSACTION", fin)
        self.assertIn("ESCALATE_TO_ANALYST", fin)

    def test_r5_card_testing(self):
        plan = names(initial_plan(ctx(p=0.8, pattern="card_testing", card_testing_big_cleared=True), None))
        for a in ("DECLINE_TRANSACTION", "STEP_UP_AUTH", "BLOCK_CARD"):
            self.assertIn(a, plan)

    def test_r6_shared_origin_reports_and_monitors(self):
        c = ctx(p=0.9, n_fraud_groups=2, shared_origin="device profile X", connected_cards=["C00002-K1"], undocumented=True)
        plan = names(initial_plan(c, None))
        for a in ("CREATE_CASE", "FILE_REPORT", "MONITOR_CONNECTED_CARDS", "ESCALATE_TO_ANALYST"):
            self.assertIn(a, plan)

    def test_r7_recurring_dispute_never_blocks(self):
        c = ctx(trigger="customer_report", p=0.2, recurring_dispute=True)
        init = initial_plan(c, "customer_validation")
        self.assertEqual(set(names(init)), {"CREATE_CASE", "VERIFY_WITH_CUSTOMER", "WARN_CUSTOMER"})
        self.assertNotIn("BLOCK_CARD", names(final_plan(c, "confirm", init)))

    def test_r10_block_all_only_with_two_fraud_cards(self):
        self.assertNotIn("BLOCK_ALL_CARDS", names(final_plan(ctx(p=0.9), "deny", initial_plan(ctx(p=0.9), "customer_validation"))))
        c = ctx(p=0.9, fraud_cards_of_customer=2)
        self.assertIn("BLOCK_ALL_CARDS", names(final_plan(c, "deny", initial_plan(c, "customer_validation"))))

    def test_sar_requires_fraud_verdict(self):
        self.assertFalse(sar_required(ctx(exposure=5000), "uncertain")[0])
        self.assertTrue(sar_required(ctx(exposure=5000), "fraud")[0])
        self.assertTrue(sar_required(ctx(exposure=50, undocumented=True), "fraud")[0])


class DetectorTests(unittest.TestCase):
    def test_card_testing_sequence(self):
        w = [txn(1, "2016-11-14 09:12:00", 1.10), txn(2, "2016-11-14 09:30:00", 2.40), txn(3, "2016-11-14 09:52:00", 0.95),
             txn(4, "2016-11-14 10:31:00", 259.98)]
        s = D.card_testing(w[3], w)
        self.assertIsNotNone(s)
        self.assertTrue(s.data["big_cleared"])
        self.assertEqual(len(s.data["affected"]), 4)

    def test_two_small_auths_are_not_card_testing(self):
        w = [txn(1, "2016-11-14 09:12:00", 1.10), txn(2, "2016-11-14 09:30:00", 2.40), txn(4, "2016-11-14 10:31:00", 259.98)]
        self.assertIsNone(D.card_testing(w[2], w))

    def test_structuring(self):
        w = [txn(1, "2016-11-21 20:00:00", 478.95), txn(2, "2016-11-21 20:10:00", 456.96), txn(3, "2016-11-21 20:24:00", 488.04),
             txn(4, "2016-11-21 20:30:00", 482.12)]
        s = D.structuring(w[3], w)
        self.assertEqual(round(sum(t["amt"] for t in s.data["affected"]), 2), 1906.07)

    def test_ring_requires_homogeneity_and_rarity(self):
        win = [txn(i, f"2016-12-0{i} 10:00:00", 100.0 + i / 100, card_id=f"C0000{i}-K1", product="R", device_id="D1",
                   p_email="verizon.net", r_email="gmail.com") for i in range(1, 6)]
        nb = {"device": {"profile": "Windows | other | chrome 61.0 | 1280x720", "n_cards": 5}, "window_txns": win,
              "window_days": 14, "closed_cases": []}
        s = D.device_ring(win[0], nb)
        self.assertIsNotNone(s)
        self.assertEqual(len(s.data["connected_cards"]), 4)
        nb["device"]["n_cards"] = 500                        # popular profile: not a ring
        self.assertIsNone(D.device_ring(win[0], nb))

    def test_recurrence_needs_regular_cadence(self):
        flag = txn(9, "2016-12-04 19:55:28", 77.07, channel="in_person", product="W", addr1=444.0)
        weekly = {"hits": [{"txn_id": i, "ts": f"2016-11-{d:02d} 19:00:00"} for i, d in enumerate((5, 12, 19, 26))], "scope_n": 10}
        self.assertIsNotNone(D.recurrence_signal(flag, weekly))
        same_day = {"hits": [{"txn_id": 1, "ts": "2016-09-27 19:11:40"}, {"txn_id": 2, "ts": "2016-09-27 19:13:08"},
                             {"txn_id": 3, "ts": "2016-12-03 23:28:08"}], "scope_n": 30}
        self.assertIsNone(D.recurrence_signal(flag, same_day))

    def test_out_of_region_vs_trip(self):
        flag = txn(1, "2016-12-04 12:00:00", 80, channel="in_person", addr1=999.0)
        home = txn(2, "2016-12-04 18:00:00", 30, channel="in_person", addr1=204.0)
        self.assertEqual(D.region_signal(flag, {"n": 0}, [flag, home]).key, "out_of_region")
        trip = [txn(10 + d, f"2016-12-0{4 + d} 12:00:00", 50, channel="in_person", addr1=999.0) for d in range(3)]
        self.assertEqual(D.region_signal(flag, {"n": 0}, [flag] + trip).key, "trip")


if __name__ == "__main__":
    unittest.main()

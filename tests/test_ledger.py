import unittest

from ledger import (
    delete_spend_balance_delta,
    edit_spend_balance_delta,
    normalize_spend_amount,
    recalculate_balances,
    spend_balance_delta,
    split_balance,
    split_share,
    sync_balance_delta,
)


class LedgerMathTests(unittest.TestCase):
    def test_split_share_divides_evenly(self):
        self.assertEqual(split_share(300, 3), 100.0)
        self.assertEqual(split_share(100, 4), 25.0)

    def test_split_share_rejects_zero_people(self):
        with self.assertRaises(ValueError):
            split_share(100, 0)

    def test_split_balance_compares_spent_to_share(self):
        self.assertEqual(split_balance(150, 100), 50.0)
        self.assertEqual(split_balance(75, 100), -25.0)
        self.assertEqual(split_balance(100, 100), 0.0)

    def test_spend_reduces_balance(self):
        self.assertEqual(spend_balance_delta(150), -150.0)

    def test_legacy_negative_amount_normalizes(self):
        self.assertEqual(normalize_spend_amount(-80), 80.0)
        self.assertEqual(spend_balance_delta(-80), -80.0)

    def test_edit_spend_delta(self):
        self.assertEqual(edit_spend_balance_delta(100, 80), 20.0)
        self.assertEqual(edit_spend_balance_delta(80, 100), -20.0)

    def test_edit_legacy_negative_old_amount(self):
        self.assertEqual(edit_spend_balance_delta(-50, 50), 0.0)
        self.assertEqual(edit_spend_balance_delta(-50, 75), -25.0)

    def test_delete_restores_spend(self):
        self.assertEqual(delete_spend_balance_delta(120), 120.0)
        self.assertEqual(delete_spend_balance_delta(-120), 120.0)

    def test_sync_delta(self):
        self.assertEqual(sync_balance_delta(1000, 1250), 250.0)
        self.assertEqual(sync_balance_delta(1250, 1000), -250.0)

    def test_recalculate_balances_chain(self):
        deltas = [-100.0, 20.0, 50.0, -30.0]
        self.assertEqual(recalculate_balances(deltas), [-100.0, -80.0, -30.0, -60.0])

    def test_round_money_precision(self):
        self.assertEqual(split_share(100, 3), 33.33)


if __name__ == '__main__':
    unittest.main()

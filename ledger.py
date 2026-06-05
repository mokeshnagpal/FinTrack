"""Pure balance and split math used by FinTrak (no Firestore or Flask dependencies)."""

from __future__ import annotations


def round_money(value) -> float:
    return round(float(value), 2)


def split_share(total_spent, num_people) -> float:
    if num_people <= 0:
        raise ValueError('At least one participant is required to calculate a split share.')
    return round_money(float(total_spent) / float(num_people))


def split_balance(spent, share_amount) -> float:
    return round_money(float(spent) - float(share_amount))


def normalize_spend_amount(amount) -> float:
    """Transaction amounts are stored as positive spend values."""
    raw = float(amount)
    return round_money(abs(raw) if raw < 0 else raw)


def spend_balance_delta(amount) -> float:
    """Balance change when recording a new expense transaction."""
    return round_money(-normalize_spend_amount(amount))


def edit_spend_balance_delta(old_amount, new_amount) -> float:
    """Balance correction when an expense amount changes."""
    old = normalize_spend_amount(old_amount)
    new = normalize_spend_amount(new_amount)
    return round_money(old - new)


def delete_spend_balance_delta(amount) -> float:
    """Balance restoration when a spend transaction is deleted."""
    return normalize_spend_amount(amount)


def sync_balance_delta(previous_balance, new_absolute_balance) -> float:
    return round_money(float(new_absolute_balance) - float(previous_balance))


def recalculate_balances(deltas) -> list[float]:
    """Replay ledger deltas and return the running balance after each row."""
    current = 0.0
    balances: list[float] = []
    for delta in deltas:
        current = round_money(current + float(delta))
        balances.append(current)
    return balances

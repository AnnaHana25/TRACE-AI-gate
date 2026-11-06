"""
Тестування алгоритму хеш-ланцюга на підроблених даних (сценарії Т1-Т7).
Запуск з папки проєкту:  python -m pytest tests -v
Результати використано в таблиці 4.1 курсової роботи.
"""

import copy
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from hashchain import (
    GENESIS_HASH,
    build_chain,
    compute_hash,
    reconcile,
    verify_chain,
)  # noqa: E402


def make_events(count=21):
    """Еталонні події журналу."""
    events = []
    for i in range(count):
        kind = ["action_approved", "action_blocked", "action_pending"][i % 3]
        events.append(
            {
                "event_type": kind,
                "event_time": f"2026-10-25T15:{i:02d}:00.000Z",
                "payload": json.dumps(
                    {"actionId": f"act_{i}", "target": f"src/file_{i}.ts"}
                ),
            }
        )
    return events


def fresh_chain():
    return build_chain(make_events())


def rehash_from(chain, start):
    """Допоміжна функція атакуючого: перераховує всі хеші, починаючи з позиції start."""
    prev = chain[start]["prev_hash"]
    for e in chain[start:]:
        e["prev_hash"] = prev
        e["current_hash"] = compute_hash(
            prev, e["seq"], e["event_type"], e["event_time"], e["payload"]
        )
        prev = e["current_hash"]


def test_clean_chain_is_ok():
    report = verify_chain(fresh_chain())
    assert report["ok"] is True
    assert report["total"] == 21
    assert report["break_type"] == "none"


def test_first_entry_uses_genesis_hash():
    assert fresh_chain()[0]["prev_hash"] == GENESIS_HASH


def test_hash_is_deterministic():
    assert fresh_chain()[-1]["current_hash"] == fresh_chain()[-1]["current_hash"]


def test_t1_payload_changed_without_rehash():
    chain = fresh_chain()
    chain[7]["payload"] = json.dumps({"actionId": "act_7", "verdict": "approved"})
    report = verify_chain(chain)
    assert not report["ok"]
    assert report["first_broken_seq"] == 8
    assert report["break_type"] == "hash_mismatch"


def test_t2_current_hash_recomputed_only_for_one_entry():
    chain = fresh_chain()
    chain[7]["payload"] = json.dumps({"actionId": "act_7", "verdict": "approved"})
    e = chain[7]
    e["current_hash"] = compute_hash(
        e["prev_hash"], e["seq"], e["event_type"], e["event_time"], e["payload"]
    )
    report = verify_chain(chain)
    assert not report["ok"]
    assert report["first_broken_seq"] == 9  # розрив видно на наступному записі
    assert report["break_type"] == "chain_broken"


def test_t3_entry_deleted():
    chain = fresh_chain()
    del chain[9]
    report = verify_chain(chain)
    assert not report["ok"]
    assert report["first_broken_seq"] == 11


def test_t4_fake_entry_inserted():
    chain = fresh_chain()
    fake = copy.deepcopy(chain[8])
    fake["payload"] = json.dumps({"actionId": "fake", "verdict": "approved"})
    chain.insert(8, fake)
    assert not verify_chain(chain)["ok"]


def test_t5_entries_swapped():
    chain = fresh_chain()
    chain[7], chain[8] = chain[8], chain[7]
    assert not verify_chain(chain)["ok"]


def test_t6_tail_cut_is_not_seen_by_chain_but_seen_by_reconcile():
    original = fresh_chain()
    cut = original[:-3]
    assert verify_chain(cut)["ok"] is True  # сам ланцюг цього не бачить
    diffs = reconcile(cut, original)  # а звірка з оригіналом бачить
    assert [d["seq"] for d in diffs] == [19, 20, 21]


def test_t7_full_resync_is_not_seen_by_chain_but_seen_by_reconcile():
    original = fresh_chain()
    forged = copy.deepcopy(original)
    forged[7]["payload"] = json.dumps({"actionId": "act_7", "verdict": "approved"})
    rehash_from(forged, 7)
    assert verify_chain(forged)["ok"] is True  # ланцюг формально цілий
    diffs = reconcile(forged, original)
    assert diffs and diffs[0]["seq"] == 8


def test_reconcile_equal_copies():
    chain = fresh_chain()
    assert reconcile(copy.deepcopy(chain), chain) == []


def test_performance_10000_entries():
    events = [
        {
            "event_type": "action_approved",
            "event_time": "2026-10-25T15:00:00.000Z",
            "payload": json.dumps({"i": i}),
        }
        for i in range(10_000)
    ]
    start = time.perf_counter()
    chain = build_chain(events)
    build_ms = (time.perf_counter() - start) * 1000
    start = time.perf_counter()
    report = verify_chain(chain)
    verify_ms = (time.perf_counter() - start) * 1000
    print(f"\nN=10000: побудова {build_ms:.0f} мс, перевірка {verify_ms:.0f} мс")
    assert report["ok"]
    assert verify_ms < 2000

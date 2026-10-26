# user_enumeration.py
# 2026 Joey Manani & Anchorfish Team
#
# Attack: tell real usernames from fake ones by timing the login reply. 
# A known user runs argon2 on its stored hash; without the defence an unknown user skips that and answers faster.
#
# Toggle LOGIN_TIMING_DEFENCE=false (vulnerable) vs true (defended).
#
# You gotta turn LOGIN_RATE_LIMIT off (or set it high) for this run, or the 429s drown the timing
# Usage: python -m redteam.user_enumeration


import time
from statistics import median
from redteam.common import post, verdict



SAMPLES = 15
KNOWN = "admin"                 # seeded account, definitely exists
UNKNOWN = "gheruygosdfudsyvf"   # almost certainly does not
GAP_SECONDS = 0.02              # a real timing signal is far bigger than noise at this sample

BAR_WIDTH = 40   # longest bar, in characters


def median_time(username: str) -> float:
    times = []
    for _ in range(SAMPLES):
        start = time.perf_counter()
        post("/api/login", {"username": username, "password": "i really dislike broccoli"})
        times.append(time.perf_counter() - start)
    return median(times)


def bar(seconds: float, longest: float) -> str:
    filled = round(BAR_WIDTH * seconds / longest) if longest else 0
    return "█" * filled + "·" * (BAR_WIDTH - filled)


def chart(known: float, unknown: float) -> None:
    longest = max(known, unknown)
    print("\n  Median login reply time (bigger = slower):\n")
    print(f"  known    {KNOWN:<16} {bar(known, longest)}  {known*1000:.1f} ms")
    print(f"  unknown  {UNKNOWN:<16} {bar(unknown, longest)}  {unknown*1000:.1f} ms")
    print(f"  {'gap':<26}{bar(abs(known - unknown), longest)}  {(known - unknown)*1000:+.1f} ms")


def run() -> None:
    known = median_time(KNOWN)
    unknown = median_time(UNKNOWN)
    gap = known - unknown
    chart(known, unknown)
    verdict(
        "Username enumeration via login timing",
        vulnerable=gap > GAP_SECONDS,
        evidence=(f"known user {known*1000:.0f} ms vs unknown {unknown*1000:.0f} ms "
                  f"(gap {gap*1000:+.0f} ms) - {'the gap leaks which usernames exist' if gap > GAP_SECONDS else 'times match, no leak'}"),
    )

if __name__ == "__main__":
    run()



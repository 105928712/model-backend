# idor_history.py
# 2026 Joey Manani & Anchorfish Team
#
# Attack: broken access control (IDOR). Log in as sienna and try to read and delete joey's saved
# checks by their id, plus the obvious variations: every one of joey's ids, sienna's own list,
# odd-looking ids, and no token or a fake one.
#
# Set ACCESS_CONTROL=false in .env to drop the owner filter and watch the read and delete get through.
# About 25 requests per run, so an off run and an on run fit inside the 60 a minute rate limit.
#
# Usage: python -m redteam.idor_history

from redteam.common import delete, get, login, seed_password, verdict

SWEEP = 10  # how many of joey's ids sienna tries to read
ODD_IDS = ["0", "-1", str(2**31), "1%20OR%201=1", "1.0"]  # out of range or not a number -> 422. "1.0" is read as id 1, so it gets the owner check like any other id


def run() -> None:
    joey   = login("joey", seed_password("joey"))
    sienna = login("sienna", seed_password("sienna"))

    if not (joey and sienna):
        print("  (skipped: could not log in as joey and sienna - seed the database first)")
        return

    joey_ids = [item["id"] for item in get(f"/api/history?limit={SWEEP}", token=joey)[1]]
    if not joey_ids:
        print("  (skipped: joey has no saved checks to target - re-seed the database)")
        return
    target_id = joey_ids[0]

    # Variation 1: does sienna's own list show any of joey's checks?
    sienna_ids = {item["id"] for item in get("/api/history?limit=100", token=sienna)[1]}
    shared = sienna_ids & set(joey_ids)
    verdict("IDOR variation: joey's checks in sienna's list", vulnerable=bool(shared),
            evidence=f"{len(shared)} of joey's {len(joey_ids)} checks showed up in sienna's list")

    # Variation 2: walk every one of joey's ids, not just one
    sweep = [get(f"/api/history/{check_id}", token=sienna)[0] for check_id in joey_ids]
    verdict(f"IDOR variation: sienna reading all {len(joey_ids)} of joey's ids", vulnerable=200 in sweep,
            evidence=f"{sweep.count(200)} read, {sweep.count(404)} got 404, other codes: {sorted(set(sweep) - {200, 404})}")

    # Variation 3: odd ids that might slip past the id check
    odd = {check_id: get(f"/api/history/{check_id}", token=sienna)[0] for check_id in ODD_IDS}
    verdict("IDOR variation: odd-looking ids", vulnerable=200 in odd.values(),
            evidence=", ".join(f"{check_id} -> {status}" for check_id, status in odd.items()))

    # Variation 4: no token, and a fake one
    no_token = get(f"/api/history/{target_id}")[0]
    fake     = get(f"/api/history/{target_id}", token="not.a.realtoken")[0]
    verdict("IDOR variation: no token / fake token", vulnerable=200 in (no_token, fake),
            evidence=f"no token HTTP {no_token}, fake token HTTP {fake}")

    # The main attack. Delete goes last, because with the defence off it really deletes joey's check
    read_status, _ =    get(f"/api/history/{target_id}", token=sienna)
    del_status, _  = delete(f"/api/history/{target_id}", token=sienna)
    leaked = read_status == 200 or del_status == 204  # if either worked, BAD!!
    verdict(
        f"IDOR: sienna reaching joey's check id {target_id}",
        vulnerable=leaked,
        evidence=(f"read HTTP {read_status}, delete HTTP {del_status} - "
                  f"{'another user accessed the record' if leaked else 'both 404, record stays private to its owner'}"),
    )


if __name__ == "__main__":
    run()

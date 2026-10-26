# idor_history.py
# 2026 Joey Manani & Anchorfish Team
#
# Attack: broken access control (IDOR). Log in as sienna and try to read and delete joey's saved
# checks by my id. 
#
# Always defended (no toggle): every history query is scoped to WHERE user_id,
# so another user's id just returns 404. This proves the access control holds.
# disabling this is kinda silly
#
# Usage: python -m redteam.idor_history

from redteam.common import delete, get, login, seed_password, verdict

def run() -> None:
    joey   = login("joey", seed_password("joey"))
    sienna = login("sienna", seed_password("sienna"))

    if not (joey and sienna):
        print("  (skipped: could not log in as joey and sienna - seed the database first)")
        return

    joey_history = get("/api/history", token=joey)[1]
    if not joey_history:
        print("  (skipped: joey has no saved checks to target - re-seed the database)")
        return
    target_id = joey_history[0]["id"]

    read_status, _ =    get(f"/api/history/{target_id}", token=sienna)
    del_status, _  = delete(f"/api/history/{target_id}", token=sienna)
    leaked = read_status == 200 or del_status == 204 # if either worked, BAD!!
    verdict(
        f"IDOR: sienna reaching joey's check id {target_id}",
        vulnerable=leaked,
        evidence=(f"read HTTP {read_status}, delete HTTP {del_status} - "
                  f"{'another user accessed the record' if leaked else 'both 404, record stays private to its owner'}"),
    )

if __name__ == "__main__":
    run()
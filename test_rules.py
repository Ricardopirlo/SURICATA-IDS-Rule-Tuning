"""
test_rules.py (fixed v3)
Test suite for the rules defined in local.rules.

Change history:
  v2 -> v3:
    FIX: On Windows, subprocess.run(..., shell=True) invokes cmd.exe,
    which does NOT interpret single quotes ('...') as string delimiters
    (unlike Bash on Linux/macOS). As a result, curl commands with URLs
    enclosed in single quotes were passed incorrectly to the container,
    causing curl exit code 3 (malformed URL) during the SQL injection
    tests. Those URLs have been changed to use double quotes, which are
    compatible with cmd.exe.
    Also replaces the deprecated datetime.utcnow() with
    datetime.now(UTC).replace(tzinfo=None).

  v1 -> v2:
    CRITICAL FIX: check_alert() previously reread the entire eve.json
    file from the beginning on every call without filtering by time.
    Since eve.json is an append-only log, an alert generated during a
    previous test (for example, the real scan in Test 2) could still be
    found during later tests that expected NOT to see that alert
    (for example, the negative case in Test 3), producing a false
    positive caused by the test harness rather than Suricata itself.
    Each test now records its own start timestamp and only considers
    alerts whose event.timestamp is greater than or equal to that value.

  (v1 -> original):
    - Added real verification against eve.json (previously only verified
      that the Docker command executed successfully).
    - Added a negative test case (benign traffic should not trigger an alert).
    - Targets now point to the "victim" container defined in docker-compose.
"""

import json
import subprocess
import time
from datetime import datetime, UTC

EVE_LOG = "logs/eve.json"
VICTIM_HOST = "172.18.0.2"  # IP address of the 'victim' container on the
                             # lab_net network (verify with:
                             # docker inspect lab_victim)


def print_header(text):
    print("\n" + "=" * 60)
    print(f" {text}")
    print("=" * 60)


def run_command(description, command):
    print(f"\n▶ [{description}]")
    print(f"  Executing: {command}")
    try:
        subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        print("  Command status: executed successfully")
    except subprocess.CalledProcessError as e:
        print(f"  Command status: exited with a non-zero code (expected for some attack tools) - {e}")


def _parse_eve_timestamp(ts_str):
    """
    eve.json timestamps use ISO8601 format with microseconds
    and a timezone offset, for example:
        2026-08-02T19:50:00.440579+0000

    The string is truncated to the first 26 characters, leaving:
        YYYY-MM-DDTHH:MM:SS.ffffff

    This allows parsing without depending on the timezone offset.
    """
    try:
        return datetime.strptime(ts_str[:26], "%Y-%m-%dT%H:%M:%S.%f")
    except (ValueError, TypeError):
        return None


def check_alert(sid, log_path=EVE_LOG, timeout=8, poll_interval=0.5, since=None):
    """
    Searches eve.json for an alert event with the expected signature_id,
    generated AFTER the timestamp specified in 'since'.

    since: naive UTC datetime marking the starting point. If omitted,
    the current time is used, meaning only newly generated alerts are
    considered and previously existing alerts in the log are ignored.
    """
    if since is None:
        since = datetime.now(UTC).replace(tzinfo=None)

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(log_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    if event.get("event_type") != "alert":
                        continue

                    if event.get("alert", {}).get("signature_id") != sid:
                        continue

                    event_ts = _parse_eve_timestamp(event.get("timestamp", ""))
                    if event_ts is None:
                        continue

                    if event_ts >= since:
                        return True

        except FileNotFoundError:
            pass

        time.sleep(poll_interval)

    return False


def run_test(description, command, expected_sid, should_alert=True):
    """
    Executes a test case and validates the expected outcome against
    eve.json, considering only alerts generated after THIS test started.
    """
    start_time = datetime.now(UTC).replace(tzinfo=None)  # Record start time before launching the attack

    run_command(description, command)
    fired = check_alert(expected_sid, since=start_time)

    if should_alert:
        if fired:
            print(f"  ✅ PASS: SID {expected_sid} triggered as expected")
        else:
            print(f"  ❌ FAIL: Expected SID {expected_sid}, but no alert was found in eve.json")
    else:
        if not fired:
            print(f"  ✅ PASS: SID {expected_sid} correctly did NOT trigger (benign traffic)")
        else:
            print(f"  ❌ FAIL: SID {expected_sid} triggered on benign traffic (false positive)")

    return fired == should_alert


def main():
    print_header("STARTING AUTOMATED IDS TEST SUITE - SURICATA")
    results = []

    # ------------------------------------------------------------------
    # Test 1: ICMP Ping Discovery (positive)
    # ------------------------------------------------------------------
    results.append(run_test(
        "1/5 - ICMP Traffic Test (Ping) -- expect SID 1000001",
        f"docker run --rm --network host alpine ping -c 3 {VICTIM_HOST}",
        expected_sid=1000001,
        should_alert=True,
    ))
    time.sleep(3)

    # ------------------------------------------------------------------
    # Test 2: Real TCP SYN Port Scan (positive)
    # ------------------------------------------------------------------
    results.append(run_test(
        "2/5 - TCP SYN Port Scan (Nmap, ports 1-100) -- expect SID 1000002",
        f"docker run --rm --network host instrumentisto/nmap -sS -p 1-100 {VICTIM_HOST}",
        expected_sid=1000002,
        should_alert=True,
    ))

    # Rule 1000002 uses a threshold window of 5 seconds
    # (count 15, seconds 5). Wait longer to ensure the counter
    # has been reset before executing the negative test.
    time.sleep(8)

    # ------------------------------------------------------------------
    # Test 3 (negative): A single normal TCP connection should NOT
    # trigger the scan rule after the threshold fix.
    #
    # Uses curlimages/curl (curl already installed) instead of
    # installing curl inside Alpine with apk, avoiding additional
    # SYN packets to external package mirrors that could affect
    # the by_src threshold counter.
    # ------------------------------------------------------------------
    results.append(run_test(
        "3/5 - Single benign TCP connection -- expect NO alert on SID 1000002",
        f"docker run --rm --network host curlimages/curl -s http://{VICTIM_HOST}/",
        expected_sid=1000002,
        should_alert=False,
    ))
    time.sleep(3)

    # ------------------------------------------------------------------
    # Test 4: SQL Injection UNION SELECT (positive)
    # ------------------------------------------------------------------
    results.append(run_test(
        "4/5 - SQL Injection Attempt (HTTP UNION SELECT) -- expect SID 1000003",
        f'docker run --rm --network host curlimages/curl -s '
        f'"http://{VICTIM_HOST}/index.php?id=1%27%20UNION%20SELECT%201,2,3--"',
        expected_sid=1000003,
        should_alert=True,
    ))
    time.sleep(3)

    # ------------------------------------------------------------------
    # Test 5: Time-Based Blind SQL Injection (positive)
    # ------------------------------------------------------------------
    results.append(run_test(
        "5/5 - SQL Injection Attempt (Time-Based Blind) -- expect SID 1000005",
        f'docker run --rm --network host curlimages/curl -s '
        f'"http://{VICTIM_HOST}/index.php?id=1%20AND%20SLEEP(5)"',
        expected_sid=1000005,
        should_alert=True,
    ))

    print_header("TEST SUMMARY")

    passed = sum(1 for r in results if r)
    total = len(results)

    print(f"  {passed}/{total} tests passed")

    if passed == total:
        print("  ✅ ALL TESTS PASSED")
    else:
        print("  ❌ SOME TESTS FAILED — review eve.json for details")


if __name__ == "__main__":
    main()

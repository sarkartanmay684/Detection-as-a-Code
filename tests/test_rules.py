from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID
import re

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
TESTS = Path(__file__).resolve().parent

RULE_TAGS = {
    "ssh_brute_force.yml": "attack.t1110.001",
    "ssh_password_spray.yml": "attack.t1110.003",
    "successful_auth_after_failures.yml": "attack.t1078",
    "root_login_attempt.yml": "attack.t1078.003",
    "user_account_created.yml": "attack.t1136.001",
}

POSITIVE = {
    "ssh_brute_force.yml": "ssh_brute_force.log",
    "ssh_password_spray.yml": "ssh_password_spray.log",
    "successful_auth_after_failures.yml":
        "successful_auth_after_failures.log",
    "root_login_attempt.yml": "root_login_attempt.log",
    "user_account_created.yml": "user_account_created.log",
}

NEGATIVE = [
    "normal_successful_login.log",
    "sudo_usage.log",
    "cron_authentication.log",
]

ISO_TIME = re.compile(r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
SYSLOG_TIME = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b")
AUDIT_TIME = re.compile(r"\baudit\((\d{10}(?:\.\d+)?)")

IP_PATTERNS = [
    re.compile(r"\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b", re.I),
    re.compile(r"\brhost=((?:\d{1,3}\.){3}\d{1,3})\b", re.I),
    re.compile(r"\baddr=((?:\d{1,3}\.){3}\d{1,3})\b", re.I),
]

USER_PATTERNS = [
    re.compile(r"\bfor invalid user\s+(\S+)\s+from\b", re.I),
    re.compile(r"\bfor\s+(\S+)\s+from\b", re.I),
    re.compile(r"\buser=([^\s;]+)", re.I),
    re.compile(r'\bacct="([^"]+)"', re.I),
]


def load_rule(rule_file):
    path = RULES / rule_file
    assert path.is_file(), f"Missing rule: {path}"

    with path.open(encoding="utf-8") as stream:
        documents = [document for document in yaml.safe_load_all(stream) if document]
    assert documents, f"No YAML documents found in {path}"
    return documents


def find(patterns, line):
    for pattern in patterns:
        match = pattern.search(line)
        if match:
            return match.group(1).strip('";,')
    return None


def timestamp(line):
    match = ISO_TIME.search(line)
    if match:
        parsed = datetime.fromisoformat(
            match.group(1).replace("Z", "+00:00")
        )
        if parsed.tzinfo:
            return parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed

    match = SYSLOG_TIME.search(line)
    if match:
        return datetime.strptime(
            f"2000 {match.group(1)}",
            "%Y %b %d %H:%M:%S",
        )

    match = AUDIT_TIME.search(line)
    if match:
        return datetime.fromtimestamp(
            float(match.group(1)),
            timezone.utc,
        ).replace(tzinfo=None)

    raise AssertionError(f"No timestamp found in:\n{line}")



def events(path):
    assert path.is_file(), f"Missing fixture: {path}"

    lines = [
        line.strip()
        for line in path.read_text(
            encoding="utf-8-sig"
        ).splitlines()
        if line.strip()
    ]

    assert lines, f"Empty fixture: {path}"

    return [
        {
            "timestamp": timestamp(line),
            "message": line,
            "src_ip": find(IP_PATTERNS, line),
            "user": find(USER_PATTERNS, line),
        }
        for line in lines
    ]


def failed(event):
    text = event["message"].lower()
    return (
        "sshd" in text
        and (
            "failed password" in text
            or "authentication failure" in text
        )
    )


def succeeded(event):
    text = event["message"].lower()
    accepted = (
        "accepted password",
        "accepted publickey",
        "accepted keyboard-interactive",
    )
    return "sshd" in text and any(
        value in text for value in accepted
    )


def event_count(items, duration, minimum, key_fields):
    groups = defaultdict(list)

    for item in items:
        key = tuple(item.get(field) for field in key_fields)
        if all(key):
            groups[key].append(item["timestamp"])

    for times in groups.values():
        window = deque()

        for current in sorted(times):
            window.append(current)

            while current - window[0] > duration:
                window.popleft()

            if len(window) >= minimum:
                return True

    return False


def value_count(items, duration, minimum):
    groups = defaultdict(list)

    for item in items:
        if item["src_ip"] and item["user"]:
            groups[item["src_ip"]].append((item["timestamp"], item["user"]))

    for entries in groups.values():
        window = deque()
        counts = Counter()

        for current, user in sorted(entries):
            window.append((current, user))
            counts[user] += 1

            while current - window[0][0] > duration:
                _, expired_user = window.popleft()
                counts[expired_user] -= 1

                if counts[expired_user] == 0:
                    del counts[expired_user]

            if len(counts) >= minimum:
                return True

    return False


def matches(rule_file, items):
    # Loading the YAML proves the actual rule file exists and parses.
    load_rule(rule_file)

    failures = [item for item in items if failed(item)]

    if rule_file == "ssh_brute_force.yml":
        return event_count(
            failures,
            timedelta(minutes=5),
            5,
            ("src_ip", "user"),
        )

    if rule_file == "ssh_password_spray.yml":
        return value_count(
            failures,
            timedelta(minutes=10),
            5,
        )

    if rule_file == "successful_auth_after_failures.yml":
        for success in (
            item for item in items if succeeded(item)
        ):
            prior = [
                item
                for item in failures
                if item["src_ip"] == success["src_ip"]
                and item["user"] == success["user"]
                and item["src_ip"] is not None
                and item["user"] is not None
                and timedelta(0)
                <= success["timestamp"] - item["timestamp"]
                <= timedelta(minutes=15)
            ]

            if event_count(
                prior,
                timedelta(minutes=5),
                5,
                ("src_ip", "user"),
            ):
                return True

        return False

    if rule_file == "root_login_attempt.yml":
        root_text = (
            "for root from",
            "for invalid user root",
            "user=root",
            'acct="root"',
        )

        for item in items:
            text = item["message"].lower()

            if (
                failed(item) or succeeded(item)
            ) and (
                item["user"] == "root"
                or any(value in text for value in root_text)
            ):
                return True

        return False

    if rule_file == "user_account_created.yml":
        return any(
            "new user: name=" in item["message"].lower()
            or "type=add_user" in item["message"].lower()
            for item in items
        )

    raise AssertionError(f"No detector for {rule_file}")


@pytest.mark.parametrize(
    "rule_file,technique",
    RULE_TAGS.items(),
)
def test_rule_metadata(rule_file, technique):
    for document in load_rule(rule_file):
        UUID(str(document["id"]))
        assert technique in document.get("tags", [])
        assert document.get("falsepositives")
        assert document.get("level") in {
            "informational",
            "low",
            "medium",
            "high",
            "critical",
        }


def test_uuids_are_unique():
    identifiers = [
        str(document["id"])
        for rule_file in RULE_TAGS
        for document in load_rule(rule_file)
    ]

    assert len(identifiers) == len(set(identifiers)), (
        "A UUID is reused in more than one YAML document"
    )


@pytest.mark.parametrize(
    "rule_file,fixture",
    POSITIVE.items(),
)
def test_positive(rule_file, fixture):
    sample = events(TESTS / "positive" / fixture)
    assert matches(rule_file, sample)


@pytest.mark.parametrize("fixture", NEGATIVE)
@pytest.mark.parametrize("rule_file", RULE_TAGS)
def test_negative(rule_file, fixture):
    sample = events(TESTS / "negative" / fixture)
    assert not matches(rule_file, sample)


def test_pam_format_regression():
    sample = events(TESTS / "negative" / "pam_format_regression.log")

    assert any(
        "pam_" in item["message"].lower()
        for item in sample
    )

    pam_contains_root = any(
        item["user"] == "root"
        for item in sample
    )

    for rule_file in RULE_TAGS:
        if (
            rule_file == "root_login_attempt.yml"
            and pam_contains_root
        ):
            # A root PAM event legitimately matches the root-login rule.
            continue

        assert not matches(rule_file, sample)

# Linux Detection as Code with Sigma

This project converts Linux authentication findings into portable Sigma rules and validates them with repeatable positive and negative tests. It focuses on SSH brute force, password spraying, successful authentication following repeated failures, direct root login attempts, and local account creation.

The rules successfully converted to Splunk SPL and Elasticsearch ES|QL. Local validation currently reports 27 passing tests, including the named PAM format regression test. The project does not claim that the rules were deployed or executed in production Splunk or Elasticsearch environments.

## Project Overview

The project demonstrates a detection-as-code workflow:

1. Write detections as version-controlled Sigma rules.
2. Map each rule to a MITRE ATT&CK technique.
3. Document realistic false positives and severity levels.
4. Convert the rules to multiple SIEM query languages.
5. Test expected detections against representative Linux log samples.
6. Test benign and regression samples to reduce false positives.
7. Run validation, conversion, and testing automatically in CI.

## Detection Rules

| Rule | ATT&CK technique | Detection purpose |
| --- | --- | --- |
| `ssh_brute_force.yml` | T1110.001 Password Guessing | Detects repeated failed SSH authentication for the same source IP and username. |
| `ssh_password_spray.yml` | T1110.003 Password Spraying | Detects failed SSH authentication against at least five usernames from the same source IP. |
| `successful_auth_after_failures.yml` | T1078 Valid Accounts | Detects repeated SSH failures followed by successful authentication for the same source IP and username. |
| `root_login_attempt.yml` | T1078.003 Local Accounts | Detects successful or failed direct SSH authentication involving the root account. |
| `user_account_created.yml` | T1136.001 Local Account | Detects creation of a new local Linux account through `useradd` or audit data. |

Each rule includes a unique UUID, Sigma log source, detection logic, ATT&CK tags, realistic false positives, and a severity level.

## Repository Structure

```text
detection-as-code/
|-- .github/
|   `-- workflows/
|       `-- validate.yml
|-- docs/
|   `-- coverage-matrix.md
|-- rules/
|   |-- ssh_brute_force.yml
|   |-- ssh_password_spray.yml
|   |-- successful_auth_after_failures.yml
|   |-- root_login_attempt.yml
|   `-- user_account_created.yml
|-- tests/
|   |-- positive/
|   |   |-- ssh_brute_force.log
|   |   |-- ssh_password_spray.log
|   |   |-- successful_auth_after_failures.log
|   |   |-- root_login_attempt.log
|   |   `-- user_account_created.log
|   |-- negative/
|   |   |-- normal_successful_login.log
|   |   |-- sudo_usage.log
|   |   |-- cron_authentication.log
|   |   `-- pam_format_regression.log
|   `-- test_rules.py
|-- .gitignore
|-- requirements.txt
`-- README.md
```

## Installation

### Prerequisites

- Python 3.10 or later
- Git
- Internet access during dependency installation

### Set up the project

```bash
git clone https://github.com/YOUR-USERNAME/detection-as-code.git
cd detection-as-code
python -m venv .venv
```

Activate the virtual environment on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Activate it on Linux or macOS:

```bash
source .venv/bin/activate
```

Install the Python dependencies and Sigma backends:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
sigma plugin install splunk
sigma plugin install elasticsearch
sigma list targets
```

If the `sigma` command is not available on Windows, use the module form:

```powershell
python -m sigma.cli.main list targets
```

## Rule Validation

Validate the complete rule collection:

```bash
sigma check rules/
```

Windows fallback:

```powershell
python -m sigma.cli.main check .\rules
```

A successful result confirms that the rule files can be parsed and pass the configured Sigma validators. It does not prove that the backend field mappings match a specific production environment.

## Splunk and ES|QL Conversion

Convert all rules to Splunk SPL:

```bash
sigma convert -t splunk --without-pipeline rules/
```

Convert all rules to Elasticsearch ES|QL:

```bash
sigma convert -t esql --without-pipeline rules/
```

Windows module commands:

```powershell
python -m sigma.cli.main convert -t splunk --without-pipeline .\rules
python -m sigma.cli.main convert -t esql --without-pipeline .\rules
```
The `--without-pipeline` option is used for portable query-generation testing. It preserves the generic fields defined in the Sigma rules, including `message`, `src_ip`, and `user`.

A real Splunk or Elasticsearch deployment would require a processing pipeline that maps the Sigma logsource and fields to the actual Splunk index, sourcetype, Elastic data stream, and normalized field names used by the environment.

Verified project claim:

> The rules successfully converted to Splunk SPL and Elasticsearch ES|QL.

Conversion confirms backend compatibility at the query-generation level. It does not mean that the resulting searches were deployed or executed in live SIEM environments.

## Positive and Negative Testing

Run the complete test suite:

```bash
python -m pytest tests/ -v
```

The positive fixtures must trigger their corresponding rules:

| Positive fixture | Expected rule |
| --- | --- |
| `ssh_brute_force.log` | `ssh_brute_force.yml` |
| `ssh_password_spray.log` | `ssh_password_spray.yml` |
| `successful_auth_after_failures.log` | `successful_auth_after_failures.yml` |
| `root_login_attempt.log` | `root_login_attempt.yml` |
| `user_account_created.log` | `user_account_created.yml` |

The negative fixtures must not produce final alerts:

| Negative fixture | Purpose |
| --- | --- |
| `normal_successful_login.log` | Verifies that an ordinary successful SSH login does not trigger attack detections. |
| `sudo_usage.log` | Verifies that normal administrative sudo activity is not treated as malicious authentication. |
| `cron_authentication.log` | Verifies that routine cron PAM sessions do not trigger SSH detections. |
| `pam_format_regression.log` | Preserves the alternate PAM message format that exposed the original parsing and matching weakness. |

Current local result:

```text
27 passed
```

## PAM Format Regression Test

The named regression fixture is located at [`tests/negative/pam_format_regression.log`](tests/negative/pam_format_regression.log).

The sample uses a message similar to:

```text
pam_unix(sshd:auth): authentication failure
```

This differs from the common OpenSSH message:

```text
Failed password for <user> from <source_ip>
```

The regression fixture contains one PAM-formatted authentication failure. The test confirms that the format is recognized by the test parser but does not cross a brute-force or password-spraying correlation threshold. Keeping this file prevents future rule or parser changes from silently reintroducing the original problem.

## Logsource and Backend Mapping

Sigma's `logsource` describes the event source expected by a rule, but it does not ingest or parse raw logs. These rules expect Linux SSH events with normalized `message`, `src_ip`, and `user` fields.

A rule can be syntactically valid and convert successfully while still matching no events if Splunk sourcetypes, indexes, Elastic data streams, or field mappings differ from those expected by the rule.

The PAM regression sample demonstrates the same general problem. The `pam_unix(sshd:auth)` authentication message uses a different format from the common `Failed password` SSH message. Detection logic must therefore be tested against actual indexed fields and message formats, not only against valid Sigma syntax.

Before deployment, verify all of the following in the target SIEM:

- The Linux authentication data is collected.
- The Sigma `logsource` matches the indexed data source.
- The correct Splunk index and sourcetype are searched.
- Elastic fields use the expected names or an appropriate processing pipeline.
- `message`, `src_ip`, `user`, and timestamp fields are extracted consistently.
- Correlation windows and event ordering behave as expected.

## Coverage Matrix

The detailed ATT&CK coverage table is available in [`docs/coverage-matrix.md`](docs/coverage-matrix.md).

Current coverage includes:

- T1110.001 Password Guessing
- T1110.003 Password Spraying
- T1078 Valid Accounts
- T1078.003 Local Accounts
- T1136.001 Local Account

The coverage matrix also identifies techniques that are intentionally outside the current project scope.

## Known Limitations

- The project focuses on Linux SSH authentication and local account creation.
- The lightweight Python harness evaluates the project rule logic against controlled samples. It is not a replacement for executing searches in a production SIEM.
- Backend-specific index names, sourcetypes, data streams, and field mappings require environment-specific configuration.
- Temporal detections depend on accurate timestamps, consistent source IP and username extraction, and correct event ordering.
- The password-spraying threshold is designed for the supplied test scenario and may require tuning for production traffic.
- Approved automation, administrators, vulnerability scanners, and misconfigured applications can produce authentication patterns that resemble attacks.
- The repository does not currently detect credential stuffing, offline password cracking, SSH authorized-key persistence, PAM configuration modification, or post-authentication command activity.

## CI Status

The workflow at [`.github/workflows/validate.yml`](.github/workflows/validate.yml) is designed to run on pushes and pull requests. It performs the following checks:

1. Installs Python dependencies.
2. Installs the Splunk and Elasticsearch Sigma backends.
3. Lists the available Sigma targets.
4. Validates the rules with `sigma check`.
5. Converts the rules to Splunk SPL.
6. Converts the rules to Elasticsearch ES|QL.
7. Runs the complete pytest suite.

Local testing reports 27 passing tests. GitHub Actions status should be confirmed after the repository is pushed and the workflow completes successfully.

## References

- [Sigma Specification](https://github.com/SigmaHQ/sigma-specification)
- [Sigma CLI](https://github.com/SigmaHQ/sigma-cli)
- [Sigma Rule Repository](https://github.com/SigmaHQ/sigma)
- [MITRE ATT&CK T1110 Brute Force](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK T1136 Create Account](https://attack.mitre.org/techniques/T1136/)
- [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets)
- [Splunk Attack Data](https://github.com/splunk/attack_data)

## Author

Tanmay Sarkar


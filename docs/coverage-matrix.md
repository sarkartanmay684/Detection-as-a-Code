\# Detection Coverage Matrix



\## Covered techniques



| ATT\&CK ID | Technique | Sigma rule | Positive test | Status |

|---|---|---|---|---|

| T1110.001 | Password Guessing | ssh\_brute\_force.yml | ssh\_brute\_force.log | Covered |

| T1110.003 | Password Spraying | ssh\_password\_spray.yml | ssh\_password\_spray.log | Covered |

| T1078 | Valid Accounts | successful\_auth\_after\_failures.yml | successful\_auth\_after\_failures.log | Covered |

| T1078.003 | Local Accounts | root\_login\_attempt.yml | root\_login\_attempt.log | Covered |

| T1136.001 | Local Account | user\_account\_created.yml | user\_account\_created.log | Covered |



\## Known coverage gaps



| ATT\&CK ID | Technique | Current limitation |

|---|---|---|

| T1110.002 | Password Cracking | Offline password cracking is not detected |

| T1110.004 | Credential Stuffing | Reuse of leaked credentials is not distinguished |

| T1098.004 | SSH Authorized Keys | SSH key persistence is not detected |

| T1548.003 | Sudo and Sudo Caching | Sudo is currently tested only as normal negative activity |

| T1556.003 | Pluggable Authentication Modules | PAM configuration modification is not detected |

| T1021.004 | SSH | Post-authentication SSH activity is not monitored |



\## Coverage interpretation



The PAM regression fixture validates parsing and false-positive behavior for an alternate PAM authentication message. It does not provide coverage for malicious changes to PAM configuration.



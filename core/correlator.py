"""
core/correlator.py

A deliberately simple, deliberately explainable rule engine. No machine
learning, no scoring model you can't walk through line by line.

DESIGN: each rule is a plain function that takes the full list of
Finding objects for one target and returns an Alert (or None if it
doesn't fire). Rules are registered in a list at the bottom of this
file -- adding a new rule means writing one function and adding it to
that list, nothing else changes.

LANGUAGE DISCIPLINE: rules describe *observations* and *indicators that
warrant follow-up*, never unverified conclusions. A public email address
alone is not "an account is compromised." An open RDP port alone is not
"a critical vulnerability." Alerts point at what to verify next, not at
a verdict.
"""

from core.models import Finding, Alert, DataType


def rule_exposed_admin_port_with_emails(findings: list[Finding], target: str) -> Alert | None:
    emails = [f for f in findings if f.data_type == DataType.EMAIL]
    risky_ports = {"3389", "22", "23", "3306", "5432"}
    open_admin_ports = [
        f for f in findings
        if f.data_type == DataType.OPEN_PORT and f.value in risky_ports
    ]
    if emails and open_admin_ports:
        return Alert(
            rule_name="exposed_admin_port_with_emails",
            description="Administrative/remote-access port(s) observed open "
                        "alongside publicly discoverable email addresses.",
            rationale=(
                "An open administrative port (e.g. SSH, RDP, database) combined "
                "with harvested email addresses increases the practical attack "
                "surface for credential-guessing or phishing-to-access chains. "
                "This is an indicator that warrants manual verification and "
                "scoping, not a confirmed vulnerability."
            ),
            evidence=emails + open_admin_ports,
            target=target,
        )
    return None


def rule_many_subdomains(findings: list[Finding], target: str) -> Alert | None:
    subdomains = [f for f in findings if f.data_type == DataType.SUBDOMAIN]
    unique_values = {f.value for f in subdomains}
    if len(unique_values) >= 5:
        return Alert(
            rule_name="large_subdomain_footprint",
            description=f"{len(unique_values)} distinct subdomains observed.",
            rationale=(
                "A large subdomain footprint increases the number of "
                "potential entry points (forgotten staging environments, "
                "legacy services). Worth an inventory review to confirm "
                "every subdomain is intentionally maintained and patched."
            ),
            evidence=subdomains,
            target=target,
        )
    return None


def rule_low_confidence_cluster(findings: list[Finding], target: str) -> Alert | None:
    low_conf = [f for f in findings if f.confidence < 0.4]
    if len(low_conf) >= 3:
        return Alert(
            rule_name="low_confidence_cluster",
            description=f"{len(low_conf)} findings reported with confidence below 0.4.",
            rationale=(
                "Several findings in this scan carry low source confidence. "
                "This is a data-quality flag, not a security finding -- these "
                "results should be manually spot-checked before being acted on."
            ),
            evidence=low_conf,
            target=target,
        )
    return None


# Register every rule here. Adding a rule = write the function above,
# add it to this list. Nothing else in the codebase changes.
RULES = [
    rule_exposed_admin_port_with_emails,
    rule_many_subdomains,
    rule_low_confidence_cluster,
]


def run_correlation(findings: list[Finding], target: str) -> list[Alert]:
    alerts = []
    for rule_fn in RULES:
        alert = rule_fn(findings, target)
        if alert is not None:
            alerts.append(alert)
    return alerts

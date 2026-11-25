#!/usr/bin/env python3
"""
Send SBOM & Vulnerability metrics to CloudWatch.

Counts are per finding (one count per vulnerability), not per target.
"""
import json
import argparse
from typing import Any, Dict

import boto3

DEFAULT_NAMESPACE = "CI/CD/Security"


def count_by_severity(vuln_report: Dict[str, Any], severity: str) -> int:
    return sum(
        1
        for result in vuln_report.get("Results", [])
        for vuln in result.get("Vulnerabilities", [])
        if vuln.get("Severity") == severity
    )


def send_metrics(metrics: Dict[str, float], region: str, namespace: str = DEFAULT_NAMESPACE) -> None:
    client = boto3.client("cloudwatch", region_name=region)
    client.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": name, "Value": value, "Unit": "Count"}
            for name, value in metrics.items()
        ],
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vuln-report", required=True)
    parser.add_argument("--mitre-report", required=True)
    parser.add_argument("--region", default=None, help="Defaults to AWS_REGION / AWS config")
    args = parser.parse_args()

    with open(args.vuln_report, "r", encoding="utf-8") as f:
        vuln_report = json.load(f)
    with open(args.mitre_report, "r", encoding="utf-8") as f:
        mitre_report = json.load(f)

    critical = count_by_severity(vuln_report, "CRITICAL")
    high = count_by_severity(vuln_report, "HIGH")
    attack_chains = len(mitre_report.get("attack_chains", []))

    send_metrics(
        {
            "Vulnerabilities_Critical": critical,
            "Vulnerabilities_High": high,
            "MITRE_Attack_Chains": attack_chains,
        },
        region=args.region,
    )

    print(f"Metrics sent to CloudWatch: CRITICAL={critical}, HIGH={high}, Attack Chains={attack_chains}")


if __name__ == "__main__":
    main()

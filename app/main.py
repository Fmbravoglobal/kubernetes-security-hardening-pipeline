"""
Kubernetes Security Hardening Pipeline
Evaluates Kubernetes workload configurations for security
misconfigurations and generates remediation recommendations.
"""

import os
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="Kubernetes Security Hardening Pipeline",
    description="Automated security assessment for Kubernetes workload configurations.",
    version="1.0.0",
)

# ---------------------------------------------------------------------------
# Risk factors
# ---------------------------------------------------------------------------

CRITICAL_VIOLATIONS = [
    "privileged_container",
    "run_as_root",
    "host_network",
    "host_pid",
    "writable_root_filesystem",
]

HIGH_VIOLATIONS = [
    "no_resource_limits",
    "no_liveness_probe",
    "no_readiness_probe",
    "default_service_account",
    "no_security_context",
]

MEDIUM_VIOLATIONS = [
    "latest_image_tag",
    "no_pod_disruption_budget",
    "no_network_policy",
    "no_pod_security_standard",
]


class WorkloadConfig(BaseModel):
    workload_name: str
    namespace: str
    workload_type: str = "Deployment"
    privileged_container: bool = False
    run_as_root: bool = False
    host_network: bool = False
    host_pid: bool = False
    writable_root_filesystem: bool = True
    no_resource_limits: bool = True
    no_liveness_probe: bool = True
    no_readiness_probe: bool = True
    default_service_account: bool = True
    no_security_context: bool = True
    latest_image_tag: bool = False
    no_network_policy: bool = True
    image_name: Optional[str] = ""
    replicas: Optional[int] = 1


def assess_workload(config: WorkloadConfig) -> tuple[int, list[str], list[str]]:
    score = 0
    violations = []
    remediations = []

    checks = {
        "privileged_container": (40, "Container running in privileged mode",
            "Set securityContext.privileged: false"),
        "run_as_root": (35, "Container running as root user",
            "Set securityContext.runAsNonRoot: true and runAsUser: 1000"),
        "host_network": (35, "Container using host network namespace",
            "Set hostNetwork: false"),
        "host_pid": (30, "Container sharing host PID namespace",
            "Set hostPID: false"),
        "writable_root_filesystem": (25, "Root filesystem is writable",
            "Set securityContext.readOnlyRootFilesystem: true"),
        "no_resource_limits": (20, "No CPU/memory resource limits defined",
            "Add resources.limits.cpu and resources.limits.memory"),
        "no_liveness_probe": (15, "No liveness probe configured",
            "Add livenessProbe with httpGet or exec handler"),
        "no_readiness_probe": (15, "No readiness probe configured",
            "Add readinessProbe with httpGet or exec handler"),
        "default_service_account": (15, "Using default service account",
            "Create dedicated service account with minimal RBAC permissions"),
        "no_security_context": (20, "No security context defined",
            "Add securityContext with allowPrivilegeEscalation: false"),
        "latest_image_tag": (10, "Container image using 'latest' tag",
            "Pin image to specific digest or semantic version tag"),
        "no_network_policy": (15, "No NetworkPolicy applied to namespace",
            "Create NetworkPolicy to restrict pod-to-pod communication"),
    }

    for field, (points, violation_msg, remediation_msg) in checks.items():
        if getattr(config, field, False):
            score += points
            violations.append(violation_msg)
            remediations.append(remediation_msg)

    return min(score, 100), violations, remediations


def risk_level(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


@app.get("/")
def root():
    return {"message": "Kubernetes Security Hardening Pipeline is running"}


@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/assess")
def assess(config: WorkloadConfig):
    score, violations, remediations = assess_workload(config)
    level = risk_level(score)

    return {
        "workload_name": config.workload_name,
        "namespace": config.namespace,
        "workload_type": config.workload_type,
        "risk_score": score,
        "risk_level": level,
        "violation_count": len(violations),
        "violations": violations,
        "remediations": remediations,
        "assessed_at": datetime.now(timezone.utc).isoformat(),
        "compliant": score == 0,
    }

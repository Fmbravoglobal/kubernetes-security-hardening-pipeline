# Kubernetes Security Hardening Pipeline

[![Security Pipeline](https://github.com/Fmbravoglobal/kubernetes-security-hardening-pipeline/actions/workflows/security-pipeline.yml/badge.svg)](https://github.com/Fmbravoglobal/kubernetes-security-hardening-pipeline/actions)

## Overview

An automated Kubernetes workload security assessment platform that evaluates container configurations against CIS Kubernetes Benchmark, NSA/CISA Kubernetes Hardening Guidance, and Pod Security Standards. The platform identifies misconfigurations, scores risk, and generates prioritized remediation recommendations.

Infrastructure provisions a hardened EKS cluster with secrets encryption, private API endpoint, and immutable ECR repositories using Terraform.

## Architecture Components

- FastAPI risk assessment engine
- AWS EKS (hardened cluster configuration)
- AWS ECR (immutable image repository with scan-on-push)
- AWS KMS (secrets encryption)
- Terraform Infrastructure as Code
- GitHub Actions CI/CD pipeline
- pytest unit testing (15+ test cases)

## Security Checks Performed

| Check | Severity | CIS Control |
|---|---|---|
| Privileged container | CRITICAL | 5.2.1 |
| Run as root | CRITICAL | 5.2.6 |
| Host network access | CRITICAL | 5.2.4 |
| Writable root filesystem | HIGH | 5.2.2 |
| No resource limits | HIGH | 5.2.3 |
| Default service account | HIGH | 5.1.5 |
| Latest image tag | MEDIUM | 6.1.3 |
| No network policy | MEDIUM | 5.3.2 |

## Author

**Oluwafemi Alabi Okunlola** | Cloud Security Engineer
[oluwafemiokunlola308@gmail.com](mailto:oluwafemiokunlola308@gmail.com)

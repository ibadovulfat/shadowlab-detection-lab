# Security Policy

## Supported Use

ShadowLab is intended for owned, isolated lab environments and controlled security operations work. Do not run it against systems, networks, or data you do not own or explicitly control.

ShadowLab contains capabilities that can affect host or network state, including containment, quarantine, packet capture, ARP discovery, network blocker controls, and response actions. Treat those features as security tooling and test them only in approved environments.

## Reporting A Vulnerability

Please do not open public issues for vulnerabilities that could expose users, secrets, systems, or operational data.

Instead:

1. open a private security advisory on GitHub if that option is available
2. or contact the repository owner through GitHub
3. include clear reproduction details, impact, and affected files or routes

Helpful report content:

- summary of the issue
- affected route, file, or feature
- reproduction steps
- expected behavior
- actual behavior
- impact assessment
- any suggested mitigation

## Response Goals

The project will try to:

- acknowledge valid reports in a reasonable time
- reproduce and scope the issue
- prepare a fix or mitigation
- publish a coordinated update when appropriate

## Sensitive Content

Do not include:

- raw secrets or tokens
- private keys
- API keys shown in screenshots
- real production data
- sensitive personal information
- exploit payloads that are not needed to reproduce the issue

If a secret is already exposed, rotate it before reporting the issue.

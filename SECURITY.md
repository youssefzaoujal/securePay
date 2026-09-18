# Security Policy

SecurePay is an intentionally vulnerable-in-the-right-way payment and security lab. It is a simulation and must never receive real card data, production credentials, or internet-exposed traffic.

## Supported Scope

Security reports are welcome for:

- authentication, authorization, BOLA, replay, and injection controls;
- tokenization, redaction, webhook signing, and fail-closed behavior;
- CI/CD supply-chain controls and Kubernetes policies;
- detection rules, SOAR actions, and incident evidence.

## Reporting

Please do not open a public issue for a suspected vulnerability. Contact the repository owner privately through the GitHub security contact or a private security advisory.

Include:

- affected component and commit;
- concise reproduction steps using test data only;
- expected and observed behavior;
- impact assessment and a proposed mitigation, if known.

Never include real PANs, credentials, private keys, or personal data in a report.

## Lab Safety

- Use only the documented test PAN `4111111111111111`.
- Keep `.env`, certificates, kubeconfig files, and logs out of Git.
- Run attack simulations only against local lab services.
- Treat all compliance language as PCI-inspired evidence, not certification.

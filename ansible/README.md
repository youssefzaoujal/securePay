# Ansible — configuration post-déploiement (lab)

Playbook `playbooks/deploy-agents.yml` : copie des règles Falco SecurePay + Node Exporter.

```bash
ansible-playbook -i ansible/inventory/lab.yml ansible/playbooks/deploy-agents.yml
```

Le lab Docker Compose n'a pas besoin d'Ansible : les agents tournent déjà (Prometheus, Falco via manifests k8s). Ce playbook sert de **démo CV** pour un durcissement de nœud hors cluster.

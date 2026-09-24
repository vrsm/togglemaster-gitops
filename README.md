# ToggleMaster GitOps

Repositório de manifestos Kubernetes monitorado pelo ArgoCD.

## Antes do primeiro sync
1. Crie um `Secret` real no cluster (não commite segredos).
2. Atualize o `configmap.yaml` com endpoints reais.
3. As imagens iniciais apontam para os repositórios ECR; o CI/CD atualizará automaticamente as tags para o commit SHA.
4. Edite `argocd/application.yaml` com a URL real deste repositório.

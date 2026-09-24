# ToggleMaster GitOps

Repositório de manifestos Kubernetes monitorado pelo ArgoCD.

## Antes do primeiro sync
1. Crie um `Secret` real no cluster (não commite segredos).
2. Atualize o `configmap.yaml` com endpoints reais.
3. Substitua `REPLACE_ECR_REGISTRY` e `REPLACE_IMAGE_TAG` nos deployments. O CI fará a atualização das tags.
4. Edite `argocd/application.yaml` com a URL real deste repositório.

# ToggleMaster — GitOps | Fase 3

Repositório GitOps do projeto **ToggleMaster — POSTECH Tech Challenge — Fase 3**.

Este repositório contém os manifestos Kubernetes utilizados para o gerenciamento declarativo dos cinco microsserviços da aplicação por meio de **GitOps e ArgoCD**.

---

## Visão geral

O ToggleMaster é composto por cinco microsserviços:

- **Auth Service** — autenticação e gerenciamento de usuários
- **Flag Service** — gerenciamento das feature flags
- **Targeting Service** — definição e avaliação das regras de segmentação
- **Evaluation Service** — avaliação das feature flags para cada usuário
- **Analytics Service** — processamento e persistência dos eventos de avaliação

Nesta fase, o ciclo de vida dos serviços foi automatizado utilizando:

- Terraform
- Amazon EKS
- Amazon ECR
- GitHub Actions
- DevSecOps
- GitOps
- ArgoCD
- Kubernetes

---

## Arquitetura de entrega

O fluxo de implantação é baseado em GitOps:

```text
┌──────────────────────┐
│      GitHub           │
│  togglemaster-fase3   │
└──────────┬───────────┘
           │
           │ Push / Pull Request
           ▼
┌──────────────────────┐
│   GitHub Actions      │
│                      │
│ • Testes             │
│ • Lint               │
│ • SAST               │
│ • SCA                │
│ • Docker Build       │
│ • Trivy              │
└──────────┬───────────┘
           │
           │ imagem com SHA do commit
           ▼
┌──────────────────────┐
│     Amazon ECR        │
└──────────┬───────────┘
           │
           │ atualização do manifesto
           ▼
┌──────────────────────┐
│   GitOps Repository   │
│ togglemaster-gitops   │
└──────────┬───────────┘
           │
           │ ArgoCD monitora
           ▼
┌──────────────────────┐
│        ArgoCD         │
│                      │
│ Sync + Self Heal     │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│      Amazon EKS       │
│                      │
│  5 microsserviços    │
└──────────────────────┘

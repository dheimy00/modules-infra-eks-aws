# Módulo EKS

Guia rápido para utilizar o módulo EKS com arquivos separados e validações bem definidas.

---

## 📁 Estrutura de Arquivos

- `main.tf` → Recursos do EKS (cluster, SGs, IAM, node groups, add-ons, IRSA, aws-auth/Access Entries). **Sem validações**
- `variables.tf` → Declaração de variáveis (inclui `auth_mode`, `addons_wait_for_nodes`, `enable_ssh`, etc.)
- `outputs.tf` → Saídas úteis (ARNs, endpoints, SGs, node groups, add-ons etc.)
- `validators.tf` → **Validações** (pré-condições). Contém:
  - `data.aws_subnet.selected` para identificar AZs das subnets;
  - Locals de validação (AZs, escalonamento de node groups, endpoint público);
  - Recurso âncora `aws_eks_cluster._preconditions_anchor` (com `count = 0`) usando `lifecycle.precondition`.

> **Requisito:** Terraform **>= 1.3** (para uso de `lifecycle.precondition`).

---

## ⚙️ Como Funcionam as Validações

- **Subnets/AZs:** exige pelo menos **duas subnets** em **duas AZs** distintas (a menos que desativado via `validate_subnet_count = false`).
- **Node groups:** valida `min_size`, `max_size`, `desired_size` e `disk_size` (1..16384) quando `validate_node_group_scaling = true`.
- **Endpoint público:** bloqueia `0.0.0.0/0` por padrão. Para laboratórios, habilite `allow_public_endpoint_anywhere = true` conscientemente.

---

## 🔐 Requisitos de Provedor e Permissões

- Provider `aws` configurado (região e credenciais).
- Permissões para criar:
  - EKS;
  - IAM roles/policies/attachments;
  - CloudWatch Logs;
  - KMS (opcional);
  - Security Groups;
  - Launch Templates.

---

## 🔑 Modos de Autenticação (`auth_mode`)

Escolha **uma** das opções:

1. `"aws-auth"` → Cria/gerencia o ConfigMap `aws-auth` (`kubernetes_config_map`).
2. `"access-entries"` → Cria **AWS EKS Access Entries** com `aws_eks_access_policy_association`.

> ⚠️ Não use ambos — são **mutuamente exclusivos**.

---

## 🧩 IRSA (OIDC)

- Habilite com `enable_irsa = true`.
- Cria `aws_iam_openid_connect_provider` com o thumbprint raiz do emissor OIDC do EKS.
- O add-on `ebs-csi-driver` assume a Role via IRSA com trust restrito ao `ServiceAccount` `kube-system/ebs-csi-controller-sa`.

---

## 🔐 SSH nos Nodes (Opcional)

- Habilite com `enable_ssh = true` e informe `ssh_key_name`.
- O acesso é limitado ao SG dos nodes (pode ser endurecido via `node_security_group_additional_rules`).

---

## 🧱 Add-ons

- Defina em `cluster_addons` (ex.: `vpc-cni`, `coredns`, `kube-proxy`, `ebs-csi-driver`).
- Use `addons_wait_for_nodes = true` para garantir que add-ons dependentes aguardem a criação dos node groups.

---

## 🛡️ Segurança

- **Restrinja** `cluster_endpoint_public_access_cidrs` em produção.
- Ative **KMS** (`create_kms_key = true`) ou aponte `kms_key_id` para CMK existente.
- Para forçar CMK nos volumes dos nodes, use `require_cmk_for_nodes = true`.

---

## 💡 Exemplos (`terraform.tfvars`)

### Exemplo 1 — Mínimo (aws-auth + add-ons padrão)

```hcl
module "eks" {
  source = "path/to/module"

  cluster_name   = "eks-dev"
  cluster_version = "1.28"
  vpc_id         = "vpc-0123456789abcdef0"
  subnet_ids     = ["subnet-aaa111", "subnet-bbb222"]

  cluster_endpoint_private_access      = true
  cluster_endpoint_public_access       = true
  cluster_endpoint_public_access_cidrs = ["203.0.113.0/24"]

  create_kms_key               = true
  cluster_encryption_resources = ["secrets"]

  enable_cluster_logging     = true
  cluster_log_retention_days = 7

  auth_mode = "aws-auth"

  node_groups = {
    default = {
      instance_types         = ["t3.medium"]
      desired_size           = 2
      min_size               = 1
      max_size               = 4
      disk_size              = 20
      create_launch_template = true
    }
  }

  tags = {
    Environment = "dev"
    Project     = "my-eks"
  }
}
```

---

### Exemplo 2 — Access Entries (sem aws-auth)

```hcl
module "eks" {
  source = "path/to/module"

  cluster_name   = "eks-prod"
  cluster_version = "1.28"
  vpc_id         = "vpc-0abcd01234ef56789"
  subnet_ids     = ["subnet-111111", "subnet-222222", "subnet-333333"]

  cluster_endpoint_private_access = true
  cluster_endpoint_public_access  = false

  create_kms_key = false
  kms_key_id     = "arn:aws:kms:us-east-1:111122223333:key/00000000-1111-2222-3333-444444444444"

  auth_mode = "access-entries"

  access_entries = {
    platform-admins = {
      principal_arn     = "arn:aws:iam::111122223333:role/PlatformAdmins"
      type              = "STANDARD"
      kubernetes_groups = ["system:masters"]
      policy_associations = {
        admin = {
          access_scope = { type = "cluster" }
          policy_arn   = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
        }
      }
      tags = { Team = "Platform" }
    }
  }

  node_groups = {
    system = {
      instance_types = ["m6i.large"]
      desired_size   = 3
      min_size       = 3
      max_size       = 6
      disk_size      = 40
      labels         = { role = "system" }
    }
  }

  cluster_addons = {
    vpc-cni        = { most_recent = true }
    coredns        = { most_recent = true }
    kube-proxy     = { most_recent = true }
    ebs-csi-driver = { most_recent = true }
  }

  addons_wait_for_nodes       = true
  validate_subnet_count       = true
  validate_node_group_scaling = true

  cluster_tags = { Owner = "platform" }
  tags         = { Environment = "prod" }
}
```

---

### Exemplo 3 — SSH + Endpoint Público (somente LAB)

> ⚠️ **Atenção:** uso de `0.0.0.0/0` não é recomendado fora de laboratório. Restrinja a IPs específicos sempre que possível.

```hcl
module "eks" {
  source = "path/to/module"

  cluster_name   = "eks-lab"
  cluster_version = "1.28"
  vpc_id         = "vpc-0123abcd4567efgh8"
  subnet_ids     = ["subnet-aaa", "subnet-bbb"]

  auth_mode = "aws-auth"

  cluster_endpoint_public_access       = true
  cluster_endpoint_private_access      = true
  cluster_endpoint_public_access_cidrs = ["0.0.0.0/0"]
  allow_public_endpoint_anywhere       = true

  enable_ssh   = true
  ssh_key_name = "minha-chave-ec2"

  node_groups = {
    ng1 = {
      instance_types         = ["t3.large"]
      desired_size           = 1
      min_size               = 1
      max_size               = 2
      disk_size              = 30
      create_launch_template = true
    }
  }

  tags = { Environment = "lab" }
}
```

---

## 🧰 Troubleshooting

- **Falha em pré-condições:** verifique a mensagem — geralmente indica qual regra foi violada (subnets, AZs, node group, endpoint público).
- **IRSA/OIDC:** se o emissor OIDC ainda não estiver disponível durante o `plan`, execute `apply` para criar o cluster primeiro.
- **aws-auth vs Access Entries:** não misture. Prefira `access-entries` para uma governança de acesso gerenciada pela AWS.

---

## 🚀 Roadmap

- Suporte a **IPv6** (`kubernetes_network_config`).
- Opção de **Fargate Profiles**.
- Regras de SG mais restritivas com **prefix lists** / **VPC endpoints**.

---

📘 **Autor:** Dheimy  
🧾 **Versão:** 1.0.0  
📅 **Atualizado em:** novembro/2025

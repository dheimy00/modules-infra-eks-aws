# -----------------------------------------
# Variável auxiliar para cenários de laboratório
# (permite 0.0.0.0/0 no endpoint público quando for intencional)
# -----------------------------------------
variable "allow_public_endpoint_anywhere" {
  description = "Permite explicitamente 0.0.0.0/0 no endpoint público do EKS (uso não recomendado em produção)."
  type        = bool
  default     = false
}

# -----------------------------------------
# Dados das subnets para validar diversidade de AZs
# -----------------------------------------
# Obs.: só é consultado se houver ao menos 2 subnets

data "aws_subnet" "selected" {
  for_each = length(var.subnet_ids) > 0 ? toset(var.subnet_ids) : []
  id       = each.value
}

locals {
  # Regex do nome do cluster (mantido apenas se precisar usar em outras checks)
  cluster_name_regex = "^[a-zA-Z][a-zA-Z0-9-]*$"

  # Subnets e AZs
  subnets_azs  = [for s in data.aws_subnet.selected : s.availability_zone]
  distinct_azs = distinct(local.subnets_azs)
  has_two_azs  = length(local.distinct_azs) >= 2

  # Regras de scaling e disco dos node groups (lista de chaves inválidas)
  invalid_node_groups = [
    for k, v in var.node_groups : k
    if var.validate_node_group_scaling && (
      v.min_size < 0 ||
      v.max_size < v.min_size ||
      v.desired_size < v.min_size ||
      v.desired_size > v.max_size ||
      v.disk_size < 1 ||
      v.disk_size > 16384
    )
  ]

  # Endpoint público deve estar restrito quando habilitado
  public_endpoint_enabled    = var.cluster_endpoint_public_access
  public_endpoint_has_cidrs  = length(var.cluster_endpoint_public_access_cidrs) > 0
  public_endpoint_all_open   = contains(var.cluster_endpoint_public_access_cidrs, "0.0.0.0/0")
  public_endpoint_restricted = local.public_endpoint_enabled && local.public_endpoint_has_cidrs && !local.public_endpoint_all_open
}

# -----------------------------------------
# Pré-condições no recurso principal do cluster
# -----------------------------------------
resource "aws_eks_cluster" "_preconditions_anchor" {
  # Recurso âncora somente para validação (não será criado na AWS)
  # Truque: usamos um cluster "falso" com count=0 para permitir lifecycle.precondition
  # As preconditions serão avaliadas em plan/apply.
  count    = 0
  name     = "validation-anchor"
  role_arn = "arn:aws:iam::000000000000:role/validation-anchor"
  version  = "1.28"

  vpc_config {
    subnet_ids = var.subnet_ids
  }

  lifecycle {
    precondition {
      condition     = !var.validate_subnet_count || length(var.subnet_ids) >= 2
      error_message = "Validação falhou: forneça ao menos 2 subnets para o EKS (alta disponibilidade)."
    }
    precondition {
      condition     = !var.validate_subnet_count || local.has_two_azs
      error_message = "Validação falhou: as subnets devem abranger pelo menos 2 Zonas de Disponibilidade distintas."
    }
    precondition {
      condition     = length(local.invalid_node_groups) == 0
      error_message = "Validação dos node groups falhou: verifique min/max/desired e disk_size. Inválidos: ${join(", ", local.invalid_node_groups)}"
    }
    precondition {
      condition     = !(local.public_endpoint_enabled && local.public_endpoint_all_open && !var.allow_public_endpoint_anywhere)
      error_message = "Endpoint público do EKS está aberto para 0.0.0.0/0. Restrinja 'cluster_endpoint_public_access_cidrs' ou defina 'allow_public_endpoint_anywhere=true' conscientemente."
    }
  }
}

# Nota: As preconditions acima são avaliadas mesmo com count=0, servindo como "gate" de validações.
# Alternativamente, você pode mover esses blocos para o recurso real aws_eks_cluster.this
# caso prefira falhar diretamente nele.

###############################
# variables.tf – EKS
# Descrições em PT-BR e validações adicionais
###############################

variable "cluster_name" {
  description = "Nome do cluster EKS (deve iniciar com letra; apenas letras, números e hífens; máx 100 caracteres)."
  type        = string
  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9-]*$", var.cluster_name)) && length(var.cluster_name) <= 100
    error_message = "cluster_name deve iniciar com letra, conter apenas [a-zA-Z0-9-] e ter até 100 caracteres."
  }
}

variable "cluster_version" {
  description = "Versão do Kubernetes para o EKS."
  type        = string
  default     = "1.28"
}

variable "vpc_id" {
  description = "ID da VPC onde o EKS será criado."
  type        = string
}

variable "subnet_ids" {
  description = "Lista de subnets para o EKS (mínimo 2, idealmente em AZs distintas)."
  type        = list(string)
  validation {
    condition     = length(var.subnet_ids) >= 2
    error_message = "Forneça ao menos 2 subnets (em AZs distintas) para alta disponibilidade."
  }
}

variable "control_plane_subnet_ids" {
  description = "Subnets onde as ENIs do control plane serão criadas (opcional; padrão usa subnet_ids)."
  type        = list(string)
  default     = []
}

variable "enable_irsa" {
  description = "Cria o OIDC Provider para habilitar IRSA."
  type        = bool
  default     = true
}

variable "cluster_endpoint_private_access" {
  description = "Habilita endpoint privado da API do EKS."
  type        = bool
  default     = true
}

variable "cluster_endpoint_public_access" {
  description = "Habilita endpoint público da API do EKS."
  type        = bool
  default     = true
}

variable "cluster_endpoint_public_access_cidrs" {
  description = "Lista de CIDRs com acesso ao endpoint público do EKS. ATENÇÃO: restrinja em produção."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "cluster_service_ipv4_cidr" {
  description = "CIDR para IPs de Services do Kubernetes (opcional)."
  type        = string
  default     = null
}

variable "enable_cluster_logging" {
  description = "Habilita logs do plano de controle (Control Plane) do EKS."
  type        = bool
  default     = true
}

variable "cluster_log_types" {
  description = "Tipos de logs do Control Plane a habilitar."
  type        = list(string)
  default     = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
}

variable "cluster_log_retention_days" {
  description = "Dias de retenção dos logs no CloudWatch."
  type        = number
  default     = 7
}

variable "create_kms_key" {
  description = "Se true, cria uma CMK KMS para criptografia do cluster."
  type        = bool
  default     = true
}

variable "kms_key_id" {
  description = "ARN/ID da chave KMS para criptografia (usada quando create_kms_key=false)."
  type        = string
  default     = null
}

variable "kms_key_deletion_window_in_days" {
  description = "Janela (dias) de deleção programada da CMK."
  type        = number
  default     = 7
}

variable "kms_enable_key_rotation" {
  description = "Habilita rotação automática da CMK."
  type        = bool
  default     = true
}

variable "cluster_encryption_resources" {
  description = "Recursos a criptografar via KMS (ex.: ['secrets'])."
  type        = list(string)
  default     = ["secrets"]
}

variable "kms_key_policy_statements" {
  description = "Declarações adicionais a anexar na política da CMK (lista de mapas)."
  type        = list(map(string))
  default     = null
}

variable "cluster_log_kms_key_id" {
  description = "ARN da CMK para criptografar o Log Group (opcional)."
  type        = string
  default     = null
}

variable "prevent_cluster_log_group_deletion" {
  description = "Impede a destruição do Log Group (proteção)."
  type        = bool
  default     = false
}

# -------------------------------
# IAM – nomes / boundaries / path
# -------------------------------

variable "cluster_iam_role_name" {
  description = "Nome da role IAM do cluster (conflita com cluster_iam_role_name_prefix)."
  type        = string
  default     = null
}

variable "cluster_iam_role_name_prefix" {
  description = "Prefixo para gerar nome único da role IAM do cluster (conflita com cluster_iam_role_name)."
  type        = string
  default     = null
}

variable "cluster_iam_role_permissions_boundary" {
  description = "ARN da policy usada como permissions boundary da role do cluster."
  type        = string
  default     = null
}

variable "node_iam_role_name" {
  description = "Nome da role IAM dos node groups (conflita com node_iam_role_name_prefix)."
  type        = string
  default     = null
}

variable "node_iam_role_name_prefix" {
  description = "Prefixo para gerar nome único da role IAM dos nodes (conflita com node_iam_role_name)."
  type        = string
  default     = null
}

variable "node_iam_role_permissions_boundary" {
  description = "ARN da policy usada como permissions boundary da role dos nodes."
  type        = string
  default     = null
}

variable "iam_role_path" {
  description = "Path para as roles IAM."
  type        = string
  default     = "/"
}

# -------------------------------
# Timeouts
# -------------------------------

variable "cluster_timeouts" {
  description = "Timeouts (create/update/delete) do cluster."
  type = object({
    create = optional(string)
    update = optional(string)
    delete = optional(string)
  })
  default = {}
}

variable "node_group_timeouts" {
  description = "Timeouts (create/update/delete) dos node groups."
  type = object({
    create = optional(string)
    update = optional(string)
    delete = optional(string)
  })
  default = {}
}

variable "addon_timeouts" {
  description = "Timeouts (create/update/delete) dos add-ons."
  type = object({
    create = optional(string)
    update = optional(string)
    delete = optional(string)
  })
  default = {}
}

variable "addon_resolve_conflicts_default" {
  description = "Valor padrão de resolve_conflicts nos add-ons (OVERWRITE|NONE)."
  type        = string
  default     = "OVERWRITE"
  validation {
    condition     = contains(["OVERWRITE", "NONE"], var.addon_resolve_conflicts_default)
    error_message = "addon_resolve_conflicts_default deve ser OVERWRITE ou NONE."
  }
}

variable "validate_subnet_count" {
  description = "Valida que ao menos 2 subnets foram fornecidas."
  type        = bool
  default     = true
}

variable "validate_node_group_scaling" {
  description = "Valida parâmetros de scaling dos node groups."
  type        = bool
  default     = true
}

# -------------------------------
# Security Groups / Network
# -------------------------------

variable "additional_security_group_ids" {
  description = "SGs adicionais a associar ao cluster."
  type        = list(string)
  default     = []
}

variable "create_cluster_security_group" {
  description = "Cria o SG do cluster (ou usa cluster_security_group_id existente)."
  type        = bool
  default     = true
}

variable "cluster_security_group_id" {
  description = "SG existente para anexar ao cluster."
  type        = string
  default     = null
}

variable "cluster_security_group_name" {
  description = "Nome do SG do cluster (se criado)."
  type        = string
  default     = null
}

variable "cluster_security_group_description" {
  description = "Descrição do SG do cluster (se criado)."
  type        = string
  default     = "EKS cluster security group"
}

variable "cluster_security_group_additional_rules" {
  description = "Regras adicionais para o SG do cluster."
  type = map(object({
    description              = string
    protocol                 = string
    from_port                = number
    to_port                  = number
    type                     = string
    cidr_blocks              = optional(list(string))
    source_security_group_id = optional(string)
  }))
  default = {}
}

variable "create_node_security_group" {
  description = "Cria o SG dos nodes (ou usa node_security_group_id existente)."
  type        = bool
  default     = true
}

variable "node_security_group_id" {
  description = "SG existente para anexar aos node groups."
  type        = string
  default     = null
}

variable "node_security_group_name" {
  description = "Nome do SG dos nodes (se criado)."
  type        = string
  default     = null
}

variable "node_security_group_description" {
  description = "Descrição do SG dos nodes (se criado)."
  type        = string
  default     = "Security group for all nodes in the cluster"
}

variable "node_security_group_additional_rules" {
  description = "Regras adicionais para o SG dos nodes."
  type = map(object({
    description              = string
    protocol                 = string
    from_port                = number
    to_port                  = number
    type                     = string
    cidr_blocks              = optional(list(string))
    source_security_group_id = optional(string)
    self                     = optional(bool)
  }))
  default = {}
}

# -------------------------------
# Node Groups
# -------------------------------

variable "node_groups" {
  description = "Mapa de definições de Node Groups gerenciados (EKS Managed Node Groups)."
  type = map(object({
    additional_policies          = optional(list(string))
    iam_role_additional_policies = optional(list(string))
    ami_type                     = optional(string, "AL2_x86_64")
    capacity_type                = optional(string, "ON_DEMAND")
    disk_size                    = optional(number, 20)
    disk_type                    = optional(string, "gp3")
    instance_types               = optional(list(string), ["t3.medium"])
    labels                       = optional(map(string), {})
    taints = optional(list(object({
      key    = string
      value  = optional(string)
      effect = string
    })), [])
    min_size     = optional(number, 1)
    max_size     = optional(number, 10)
    desired_size = optional(number, 2)
    update_config = optional(object({
      max_unavailable_percentage = optional(number, 50)
      max_unavailable            = optional(number)
    }), {})
    launch_template_name    = optional(string)
    launch_template_version = optional(string, "$Latest")
    create_launch_template  = optional(bool, true)
    enable_monitoring       = optional(bool, true)
    block_device_mappings   = optional(list(map(string)), [])
    user_data_base64        = optional(string)
    metadata_options = optional(object({
      http_endpoint               = optional(string, "enabled")
      http_tokens                 = optional(string, "required")
      http_put_response_hop_limit = optional(number, 2)
      http_protocol_ipv6          = optional(string, "disabled")
      instance_metadata_tags      = optional(string, "disabled")
    }), {})
    tags = optional(map(string), {})
  }))
  default = {}
}

# -------------------------------
# Add-ons
# -------------------------------

variable "cluster_addons" {
  description = "Mapa de add-ons do cluster a habilitar."
  type = map(object({
    most_recent          = optional(bool, true)
    version              = optional(string)
    preserve             = optional(bool, false)
    resolve_conflicts    = optional(string)
    configuration_values = optional(string)
  }))
  default = {
    vpc-cni            = { most_recent = true }
    coredns            = { most_recent = true }
    kube-proxy         = { most_recent = true }
    aws-ebs-csi-driver = { most_recent = true }
  }
}

variable "addons_wait_for_nodes" {
  description = "Se true, força add-ons a dependerem dos node groups (útil para evitar pods pendentes)."
  type        = bool
  default     = true
}

# -------------------------------
# aws-auth vs Access Entries (mutuamente exclusivos)
# -------------------------------

variable "auth_mode" {
  description = "Modo de auth/autz no EKS: 'aws-auth' (ConfigMap) ou 'access-entries' (Access Entries)."
  type        = string
  default     = "access-entries"
  validation {
    condition     = contains(["aws-auth", "access-entries"], var.auth_mode)
    error_message = "auth_mode deve ser 'aws-auth' ou 'access-entries'."
  }
}

variable "create_aws_auth_configmap" {
  description = "Se true e auth_mode='aws-auth', cria o ConfigMap aws-auth."
  type        = bool
  default     = true
}

variable "manage_aws_auth_configmap" {
  description = "(Compat.) Indica se o módulo gerencia o aws-auth. Não é usado quando auth_mode='access-entries'."
  type        = bool
  default     = true
}

variable "aws_auth_roles" {
  description = "Roles IAM a adicionar no ConfigMap aws-auth."
  type = list(object({
    rolearn  = string
    username = string
    groups   = list(string)
  }))
  default = []
}

variable "aws_auth_users" {
  description = "Usuários IAM a adicionar no ConfigMap aws-auth."
  type = list(object({
    userarn  = string
    username = string
    groups   = list(string)
  }))
  default = []
}

variable "aws_auth_accounts" {
  description = "IDs de contas AWS a adicionar no ConfigMap aws-auth."
  type        = list(string)
  default     = []
}

# -------------------------------
# SSH opcional para nodes
# -------------------------------

variable "enable_ssh" {
  description = "Habilita bloco remote_access nos node groups."
  type        = bool
  default     = false
}

variable "ssh_key_name" {
  description = "Nome da chave EC2 para SSH (usado somente se enable_ssh=true)."
  type        = string
  default     = null
}

# -------------------------------
# Enforce CMK em volumes dos nodes (opcional)
# -------------------------------

variable "require_cmk_for_nodes" {
  description = "Se true, exige CMK específico para EBS dos nodes (falha se CMK não definido)."
  type        = bool
  default     = false
}

# -------------------------------
# Tags
# -------------------------------

variable "tags" {
  description = "Mapa de tags padrão para todos os recursos."
  type        = map(string)
  default     = {}
}

variable "cluster_tags" {
  description = "Mapa de tags aplicadas apenas ao recurso EKS Cluster."
  type        = map(string)
  default     = {}
}


variable "cluster_identity_providers" {
  description = "Mapeia provedores de identidade OIDC do EKS; a chave vira identity_provider_config_name"
  type = map(object({
    client_id       = string
    issuer_url      = optional(string) # se ausente, usa o issuer do cluster
    groups_claim    = optional(string)
    groups_prefix   = optional(string)
    required_claims = optional(map(string)) # ex.: { key = "value" }
    username_claim  = optional(string)
    username_prefix = optional(string)
  }))
  default = {}
}

variable "access_entries" {
  description = "Mapeia Access Entries para o modo auth_mode=\"access-entries\"."
  type = map(object({
    principal_arn     = string
    type              = string
    kubernetes_groups = optional(list(string))
    user_name         = optional(string)
    policy_associations = optional(map(object({
      access_scope = object({
        type       = string
        namespaces = optional(list(string))
      })
      policy_arn = string
    })))
    tags = optional(map(string))
  }))
  default = {}
}

# Permite abrir o endpoint público (0.0.0.0/0) conscientemente, útil só em LAB/POC
variable "allow_public_endpoint_anywhere" {
  description = "Permite explicitamente 0.0.0.0/0 no endpoint público do EKS (uso não recomendado em produção)."
  type        = bool
  default     = false
}

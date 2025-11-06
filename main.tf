###############################
# EKS MODULE
###############################

# ---- Datasources essenciais ----
data "aws_availability_zones" "available" { state = "available" }
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

data "aws_subnet" "selected" {
  for_each = length(var.subnet_ids) > 0 ? toset(var.subnet_ids) : []
  id       = each.value
}

# ---- Locals operacionais (sem validações) ----
locals {

  # AZs das subnets informadas
  subnets_azs  = [for s in data.aws_subnet.selected : s.availability_zone]
  distinct_azs = distinct(local.subnets_azs)
  has_two_azs  = length(local.distinct_azs) >= 2

  kms_key_id               = var.create_kms_key ? aws_kms_key.eks[0].arn : var.kms_key_id
  control_plane_subnet_ids = length(var.control_plane_subnet_ids) > 0 ? var.control_plane_subnet_ids : var.subnet_ids

  # Compatibilidade: validators.tf já faz o gate de HA; aqui mantemos a lista de subnets usada pelo cluster
  subnet_ids_validated = var.validate_subnet_count && length(var.subnet_ids) < 2 ? tolist([]) : var.subnet_ids

  # Filtro de node_groups (validação dura está em validators.tf)
  node_groups_validated = var.validate_node_group_scaling ? {
    for k, v in var.node_groups : k => v if(
      v.min_size >= 0 &&
      v.max_size >= v.min_size &&
      v.desired_size >= v.min_size &&
      v.desired_size <= v.max_size &&
      v.disk_size >= 1 &&
      v.disk_size <= 16384
    )
  } : var.node_groups

  # Lista de node groups inválidos (para mensagem de erro)
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

  # Regras de endpoint público
  public_endpoint_enabled  = var.cluster_endpoint_public_access
  public_endpoint_all_open = contains(var.cluster_endpoint_public_access_cidrs, "0.0.0.0/0")
}

########################################
# KMS (CMK opcional para criptografia do cluster)
########################################

resource "aws_kms_key" "eks" {
  count = var.create_kms_key ? 1 : 0

  description             = "EKS Cluster ${var.cluster_name} Encryption Key"
  deletion_window_in_days = var.kms_key_deletion_window_in_days
  enable_key_rotation     = var.kms_enable_key_rotation

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid       = "EnableIAMUserPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowEKSToUseKeyForCluster"
        Effect    = "Allow"
        Principal = { Service = "eks.amazonaws.com" }
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount"                          = data.aws_caller_identity.current.account_id,
            "kms:EncryptionContext:aws:eks:cluster-name" = var.cluster_name
          }
        }
      },
      {
        Sid       = "AllowCWLToUseKey"
        Effect    = "Allow"
        Principal = { Service = "logs.${data.aws_region.current.name}.amazonaws.com" }
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
        Condition = {
          ArnEquals = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
          }
        }
      }
    ], var.kms_key_policy_statements != null ? var.kms_key_policy_statements : [])
  })

  tags = merge(var.tags, var.cluster_tags, { Name = "${var.cluster_name}-eks-key" })
}

resource "aws_kms_alias" "eks" {
  count         = var.create_kms_key ? 1 : 0
  name          = "alias/${var.cluster_name}-eks"
  target_key_id = aws_kms_key.eks[0].key_id
}

########################################
# CloudWatch Log Group (sem prevent_destroy variável)
########################################

resource "aws_cloudwatch_log_group" "eks_cluster" {
  count = var.enable_cluster_logging ? 1 : 0

  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = var.cluster_log_retention_days
  kms_key_id        = var.create_kms_key ? aws_kms_key.eks[0].arn : (var.cluster_log_kms_key_id != null ? var.cluster_log_kms_key_id : null)

  tags = merge(var.tags, var.cluster_tags, { Name = "${var.cluster_name}-cluster-logs" })

  # Para proteção dura, use literal: lifecycle { prevent_destroy = true }
}

########################################
# Security Groups – Cluster e Nodes
########################################

resource "aws_security_group" "cluster" {
  count       = var.create_cluster_security_group ? 1 : 0
  name        = coalesce(var.cluster_security_group_name, "${var.cluster_name}-cluster-sg")
  description = var.cluster_security_group_description
  vpc_id      = var.vpc_id

  tags = merge(var.tags, var.cluster_tags, {
    Name                                        = "${var.cluster_name}-cluster-sg"
    "kubernetes.io/cluster/${var.cluster_name}" = "owned"
  })

  lifecycle { create_before_destroy = true }
}

resource "aws_security_group_rule" "cluster_ingress_self" {
  count                    = var.create_cluster_security_group ? 1 : 0
  description              = "Allow nodes to communicate with each other"
  from_port                = 0
  protocol                 = "-1"
  security_group_id        = aws_security_group.cluster[0].id
  source_security_group_id = aws_security_group.cluster[0].id
  to_port                  = 0
  type                     = "ingress"
}

resource "aws_security_group_rule" "cluster_egress_internet" {
  count             = var.create_cluster_security_group ? 1 : 0
  description       = "Allow cluster egress to the internet for pulling images"
  from_port         = 0
  protocol          = "-1"
  security_group_id = aws_security_group.cluster[0].id
  cidr_blocks       = ["0.0.0.0/0"]
  to_port           = 0
  type              = "egress"
}

resource "aws_security_group_rule" "cluster_additional" {
  for_each = var.create_cluster_security_group ? var.cluster_security_group_additional_rules : {}

  description              = each.value.description
  from_port                = each.value.from_port
  protocol                 = each.value.protocol
  security_group_id        = aws_security_group.cluster[0].id
  to_port                  = each.value.to_port
  type                     = each.value.type
  cidr_blocks              = lookup(each.value, "cidr_blocks", null)
  source_security_group_id = lookup(each.value, "source_security_group_id", null)
}

resource "aws_security_group" "node" {
  count       = var.create_node_security_group ? 1 : 0
  name        = coalesce(var.node_security_group_name, "${var.cluster_name}-node-sg")
  description = var.node_security_group_description
  vpc_id      = var.vpc_id

  tags = merge(var.tags, {
    Name                                        = "${var.cluster_name}-node-sg"
    "kubernetes.io/cluster/${var.cluster_name}" = "owned"
  })

  lifecycle { create_before_destroy = true }
}

resource "aws_security_group_rule" "node_ingress_self" {
  count                    = var.create_node_security_group ? 1 : 0
  description              = "Allow nodes to communicate with each other"
  from_port                = 0
  protocol                 = "-1"
  security_group_id        = aws_security_group.node[0].id
  source_security_group_id = aws_security_group.node[0].id
  to_port                  = 0
  type                     = "ingress"
}

resource "aws_security_group_rule" "node_ingress_cluster" {
  count                    = var.create_cluster_security_group && var.create_node_security_group ? 1 : 0
  description              = "Allow pods to communicate with the cluster API Server"
  from_port                = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.node[0].id
  source_security_group_id = aws_security_group.cluster[0].id
  to_port                  = 443
  type                     = "ingress"
}

resource "aws_security_group_rule" "cluster_ingress_node" {
  count                    = var.create_cluster_security_group && var.create_node_security_group ? 1 : 0
  description              = "Allow extension API servers on port 443 from control plane"
  from_port                = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.cluster[0].id
  source_security_group_id = aws_security_group.node[0].id
  to_port                  = 443
  type                     = "ingress"
}

resource "aws_security_group_rule" "node_egress_internet" {
  count             = var.create_node_security_group ? 1 : 0
  description       = "Allow nodes egress to the internet"
  from_port         = 0
  protocol          = "-1"
  security_group_id = aws_security_group.node[0].id
  cidr_blocks       = ["0.0.0.0/0"]
  to_port           = 0
  type              = "egress"
}

resource "aws_security_group_rule" "node_additional" {
  for_each = var.create_node_security_group ? var.node_security_group_additional_rules : {}

  description              = each.value.description
  from_port                = each.value.from_port
  protocol                 = each.value.protocol
  security_group_id        = aws_security_group.node[0].id
  to_port                  = each.value.to_port
  type                     = "ingress"
  cidr_blocks              = lookup(each.value, "cidr_blocks", null)
  source_security_group_id = lookup(each.value, "source_security_group_id", null)
  self                     = lookup(each.value, "self", null)
}

########################################
# IAM – Cluster
########################################

resource "aws_iam_role" "cluster" {
  name        = var.cluster_iam_role_name != null ? var.cluster_iam_role_name : (var.cluster_iam_role_name_prefix == null ? "${var.cluster_name}-cluster-role" : null)
  name_prefix = var.cluster_iam_role_name == null ? var.cluster_iam_role_name_prefix : null
  path        = var.iam_role_path

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
    }]
  })

  permissions_boundary = var.cluster_iam_role_permissions_boundary

  tags = merge(var.tags, var.cluster_tags, { Name = var.cluster_iam_role_name != null ? var.cluster_iam_role_name : "${var.cluster_name}-cluster-role" })
}

resource "aws_iam_role_policy_attachment" "cluster_policy" {
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.cluster.name
}

resource "aws_iam_role_policy_attachment" "cluster_vpc_resource_controller" {
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.cluster.name
}

########################################
# EKS Cluster
########################################

resource "aws_eks_cluster" "this" {
  name     = var.cluster_name
  role_arn = aws_iam_role.cluster.arn
  version  = var.cluster_version

  vpc_config {
    subnet_ids              = local.subnet_ids_validated
    endpoint_private_access = var.cluster_endpoint_private_access
    endpoint_public_access  = var.cluster_endpoint_public_access
    public_access_cidrs     = var.cluster_endpoint_public_access ? var.cluster_endpoint_public_access_cidrs : null
    security_group_ids = concat(
      var.create_cluster_security_group ? [aws_security_group.cluster[0].id] : [],
      var.cluster_security_group_id != null ? [var.cluster_security_group_id] : [],
      var.additional_security_group_ids
    )
  }

  encryption_config {
    provider { key_arn = local.kms_key_id }
    resources = var.cluster_encryption_resources
  }

  enabled_cluster_log_types = var.enable_cluster_logging ? var.cluster_log_types : []

  kubernetes_network_config {
    service_ipv4_cidr = var.cluster_service_ipv4_cidr
  }

  timeouts {
    create = try(var.cluster_timeouts.create, "60m")
    update = try(var.cluster_timeouts.update, "60m")
    delete = try(var.cluster_timeouts.delete, "60m")
  }

  depends_on = [
    aws_iam_role_policy_attachment.cluster_policy,
    aws_iam_role_policy_attachment.cluster_vpc_resource_controller,
    aws_cloudwatch_log_group.eks_cluster,
  ]

  tags = merge(var.tags, var.cluster_tags, { Name = var.cluster_name })

  lifecycle {
    ignore_changes = [version]

    # Pelo menos 2 subnets
    precondition {
      condition     = !var.validate_subnet_count || length(var.subnet_ids) >= 2
      error_message = "Validação falhou: forneça ao menos 2 subnets para o EKS (alta disponibilidade)."
    }

    # Subnets distribuídas em >= 2 AZs
    precondition {
      condition     = !var.validate_subnet_count || local.has_two_azs
      error_message = "Validação falhou: as subnets devem abranger pelo menos 2 Zonas de Disponibilidade distintas."
    }

    # Escalonamento/disco dos node groups
    precondition {
      condition     = length(local.invalid_node_groups) == 0
      error_message = "Validação dos node groups falhou: verifique min/max/desired e disk_size. Inválidos: ${join(", ", local.invalid_node_groups)}"
    }

    # Endpoint público aberto sem aceite explícito
    precondition {
      condition     = !(local.public_endpoint_enabled && local.public_endpoint_all_open && !var.allow_public_endpoint_anywhere)
      error_message = "Endpoint público do EKS está aberto para 0.0.0.0/0. Restrinja 'cluster_endpoint_public_access_cidrs' ou defina 'allow_public_endpoint_anywhere=true' conscientemente."
    }
  }
}

########################################
# IRSA (OIDC Provider para IAM Roles for Service Accounts)
########################################

data "tls_certificate" "eks" {
  count      = var.enable_irsa ? 1 : 0
  url        = try(aws_eks_cluster.this.identity[0].oidc[0].issuer, "")
  depends_on = [aws_eks_cluster.this]
}


resource "aws_iam_openid_connect_provider" "oidc" {
  count = var.enable_irsa ? 1 : 0

  client_id_list = ["sts.amazonaws.com"]
  # usa o último certificado (raiz) do emissor
  thumbprint_list = [
    data.tls_certificate.eks[0].certificates[
      length(data.tls_certificate.eks[0].certificates) - 1
    ].sha1_fingerprint
  ]
  url = aws_eks_cluster.this.identity[0].oidc[0].issuer

  tags = merge(var.tags, { Name = "${var.cluster_name}-irsa" })

  depends_on = [aws_eks_cluster.this]
}

########################################
# IAM – Nodes
########################################

resource "aws_iam_role" "node" {
  name        = var.node_iam_role_name != null ? var.node_iam_role_name : (var.node_iam_role_name_prefix == null ? "${var.cluster_name}-node-role" : null)
  name_prefix = var.node_iam_role_name == null ? var.node_iam_role_name_prefix : null
  path        = var.iam_role_path

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  permissions_boundary = var.node_iam_role_permissions_boundary

  tags = merge(var.tags, { Name = var.node_iam_role_name != null ? var.node_iam_role_name : "${var.cluster_name}-node-role" })
}

resource "aws_iam_role_policy_attachment" "node_worker_node_policy" {
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.node.name
}

resource "aws_iam_role_policy_attachment" "node_cni_policy" {
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.node.name
}

resource "aws_iam_role_policy_attachment" "node_container_registry_policy" {
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.node.name
}

########################################
# EBS CSI – IRSA (opcional)
########################################

resource "aws_iam_role" "ebs_csi_driver" {
  count = contains(keys(var.cluster_addons), "ebs-csi-driver") && var.enable_irsa ? 1 : 0
  name  = "${var.cluster_name}-ebs-csi-driver-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.oidc[0].arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${replace(aws_iam_openid_connect_provider.oidc[0].url, "https://", "")}:sub" = "system:serviceaccount:kube-system:ebs-csi-controller-sa",
          "${replace(aws_iam_openid_connect_provider.oidc[0].url, "https://", "")}:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })

  tags = merge(var.tags, { Name = "${var.cluster_name}-ebs-csi-driver-role" })
}

resource "aws_iam_role_policy_attachment" "ebs_csi_driver" {
  count      = contains(keys(var.cluster_addons), "ebs-csi-driver") && var.enable_irsa ? 1 : 0
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
  role       = aws_iam_role.ebs_csi_driver[0].name
}

########################################
# EKS Add-ons (depends_on estático)
########################################

resource "aws_eks_addon" "this" {
  for_each = var.cluster_addons

  cluster_name             = aws_eks_cluster.this.name
  addon_name               = each.key
  addon_version            = try(each.value.version, null)
  resolve_conflicts        = try(each.value.resolve_conflicts, var.addon_resolve_conflicts_default)
  preserve                 = try(each.value.preserve, false)
  configuration_values     = try(each.value.configuration_values, null)
  service_account_role_arn = each.key == "ebs-csi-driver" && var.enable_irsa ? try(aws_iam_role.ebs_csi_driver[0].arn, null) : null

  timeouts {
    create = try(var.addon_timeouts.create, "20m")
    update = try(var.addon_timeouts.update, "20m")
    delete = try(var.addon_timeouts.delete, "20m")
  }

  depends_on = [
    aws_eks_cluster.this,
    aws_cloudwatch_log_group.eks_cluster,
    aws_eks_node_group.this,
  ]

  tags = var.tags

  lifecycle { ignore_changes = [addon_version] }
}

########################################
# Node Groups (Managed)
########################################

resource "aws_eks_node_group" "this" {
  for_each = local.node_groups_validated

  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${var.cluster_name}-${each.key}"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = local.subnet_ids_validated
  capacity_type   = each.value.capacity_type
  instance_types  = each.value.instance_types
  ami_type        = each.value.ami_type
  disk_size       = each.value.disk_size
  labels          = each.value.labels

  dynamic "taint" {
    for_each = each.value.taints
    content {
      key    = taint.value.key
      value  = try(taint.value.value, null)
      effect = taint.value.effect
    }
  }

  scaling_config {
    desired_size = each.value.desired_size
    min_size     = each.value.min_size
    max_size     = each.value.max_size
  }

  dynamic "update_config" {
    for_each = each.value.update_config != null ? [each.value.update_config] : []
    content {
      max_unavailable_percentage = try(update_config.value.max_unavailable_percentage, null)
      max_unavailable            = try(update_config.value.max_unavailable, null)
    }
  }

  dynamic "launch_template" {
    for_each = each.value.create_launch_template || each.value.launch_template_name != null ? [1] : []
    content {
      name    = each.value.launch_template_name != null ? each.value.launch_template_name : aws_launch_template.node_group[each.key].name
      version = each.value.launch_template_version
    }
  }

  dynamic "remote_access" {
    for_each = var.enable_ssh ? [1] : []
    content {
      ec2_ssh_key               = var.ssh_key_name
      source_security_group_ids = var.create_node_security_group ? [aws_security_group.node[0].id] : []
    }
  }

  timeouts {
    create = try(var.node_group_timeouts.create, "60m")
    update = try(var.node_group_timeouts.update, "60m")
    delete = try(var.node_group_timeouts.delete, "60m")
  }

  depends_on = [
    aws_iam_role_policy_attachment.node_worker_node_policy,
    aws_iam_role_policy_attachment.node_cni_policy,
    aws_iam_role_policy_attachment.node_container_registry_policy,
    aws_eks_cluster.this,
  ]

  tags = merge(var.tags, each.value.tags, { Name = "${var.cluster_name}-${each.key}" })
}

########################################
# Launch Templates (Nodes)
########################################

locals {
  # Para cada node group, seleciona os block_device_mappings informados,
  # ou aplica um fallback com o root volume usando o disk_size do NG (ou 20).
  lt_block_device_mappings = {
    for k, v in var.node_groups :
    k => (
      length(try(v.block_device_mappings, [])) > 0
      ? try(v.block_device_mappings, [])
      : [
        {
          device_name           = "/dev/xvda"
          volume_type           = "gp3"
          volume_size           = try(v.disk_size, 20)
          encrypted             = true
          delete_on_termination = true
          # kms_key_id          = local.kms_key_id    # descomente se quiser forçar CMK aqui
          # iops                = 3000                # opcional (io1/io2)
          # throughput          = 125                 # opcional (gp3)
        }
      ]
    )
  }
}


resource "aws_launch_template" "node_group" {
  for_each = { for k, v in var.node_groups : k => v if v.create_launch_template }

  name        = coalesce(each.value.launch_template_name, "${var.cluster_name}-${each.key}-lt")
  description = "Launch template for ${var.cluster_name} node group ${each.key}"

  vpc_security_group_ids = var.create_node_security_group ? [aws_security_group.node[0].id] : []

  dynamic "block_device_mappings" {
    for_each = lookup(local.lt_block_device_mappings, each.key, [])
    content {
      device_name = block_device_mappings.value.device_name
      ebs {
        volume_type           = lookup(block_device_mappings.value, "volume_type", "gp3")
        volume_size           = lookup(block_device_mappings.value, "volume_size", try(each.value.disk_size, 20))
        encrypted             = lookup(block_device_mappings.value, "encrypted", true)
        delete_on_termination = lookup(block_device_mappings.value, "delete_on_termination", true)
        kms_key_id            = lookup(block_device_mappings.value, "kms_key_id", null)
        iops                  = lookup(block_device_mappings.value, "iops", null)
        throughput            = lookup(block_device_mappings.value, "throughput", null)
      }
    }
  }

  dynamic "metadata_options" {
    for_each = each.value.metadata_options != null ? [each.value.metadata_options] : []
    content {
      http_endpoint               = metadata_options.value.http_endpoint
      http_tokens                 = metadata_options.value.http_tokens
      http_put_response_hop_limit = metadata_options.value.http_put_response_hop_limit
      http_protocol_ipv6          = metadata_options.value.http_protocol_ipv6
      instance_metadata_tags      = metadata_options.value.instance_metadata_tags
    }
  }

  user_data = each.value.user_data_base64

  monitoring { enabled = each.value.enable_monitoring }

  tag_specifications {
    resource_type = "instance"
    tags          = merge(var.tags, each.value.tags, { Name = "${var.cluster_name}-${each.key}" })
  }

  lifecycle { create_before_destroy = true }

  tags = var.tags
}

########################################
# Enforce CMK nos nodes (opcional)
########################################

locals {
  cmk_missing = var.require_cmk_for_nodes && (var.create_kms_key == false) && (var.kms_key_id == null)
}

resource "null_resource" "cmk_enforcement" {
  count = local.cmk_missing ? 1 : 0

  provisioner "local-exec" {
    command = "echo 'ERRO: require_cmk_for_nodes=true mas nenhum KMS CMK foi definido (create_kms_key=false e kms_key_id=null).' && exit 1"
  }
}

########################################
# Provider Kubernetes (alias) + token
########################################

data "aws_eks_cluster_auth" "this" { name = aws_eks_cluster.this.name }

provider "kubernetes" {
  alias                  = "eks"
  host                   = aws_eks_cluster.this.endpoint
  cluster_ca_certificate = base64decode(aws_eks_cluster.this.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.this.token
}

########################################
# aws-auth (opcional, auth_mode = "aws-auth")
########################################

locals {
  aws_auth_configmap_yaml = <<-DOC
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: aws-auth
      namespace: kube-system
    data:
      mapRoles: |
        - rolearn: ${aws_iam_role.node.arn}
          username: system:node:{{EC2PrivateDNSName}}
          groups:
            - system:bootstrappers
            - system:nodes
        %{for role in var.aws_auth_roles~}
        - rolearn: ${role.rolearn}
          username: ${role.username}
          groups:
            %{for group in role.groups~}
            - ${group}
            %{endfor~}
        %{endfor~}
      mapUsers: |
        %{for user in var.aws_auth_users~}
        - userarn: ${user.userarn}
          username: ${user.username}
          groups:
            %{for group in user.groups~}
            - ${group}
            %{endfor~}
        %{endfor~}
      mapAccounts: |
        %{for account in var.aws_auth_accounts~}
        - ${account}
        %{endfor~}
  DOC
}

resource "kubernetes_config_map" "aws_auth" {
  count    = var.create_aws_auth_configmap && var.auth_mode == "aws-auth" ? 1 : 0
  provider = kubernetes.eks

  metadata {
    name      = "aws-auth"
    namespace = "kube-system"
    labels    = { "app.kubernetes.io/managed-by" = "Terraform" }
  }

  data = {
    mapRoles    = try(yamldecode(local.aws_auth_configmap_yaml).data.mapRoles, "")
    mapUsers    = try(yamldecode(local.aws_auth_configmap_yaml).data.mapUsers, "")
    mapAccounts = try(yamldecode(local.aws_auth_configmap_yaml).data.mapAccounts, "")
  }

  depends_on = [aws_eks_cluster.this, aws_eks_node_group.this]

  lifecycle { ignore_changes = [metadata[0].annotations] }
}


########################################
# Access Entries (opcional, auth_mode = "access-entries")
########################################

resource "aws_eks_access_entry" "this" {
  for_each = var.auth_mode == "access-entries" ? var.access_entries : {}

  cluster_name      = aws_eks_cluster.this.name
  principal_arn     = each.value.principal_arn
  kubernetes_groups = try(each.value.kubernetes_groups, [])
  type              = each.value.type
  user_name         = try(each.value.user_name, null)

  tags = merge(var.tags, try(each.value.tags, {}))
}

resource "aws_eks_access_policy_association" "this" {
  for_each = var.auth_mode == "access-entries" ? {
    for pair in flatten([
      for entry_key, entry in var.access_entries : [
        for policy_key, policy in try(entry.policy_associations, {}) : {
          access_entry_key = entry_key
          policy_key       = policy_key
          entry            = entry
          policy           = policy
        }
      ]
    ]) : "${pair.access_entry_key}-${pair.policy_key}" => pair
  } : {}

  access_scope {
    namespaces = try(each.value.policy.access_scope.namespaces, [])
    type       = each.value.policy.access_scope.type
  }

  cluster_name  = aws_eks_cluster.this.name
  policy_arn    = each.value.policy.policy_arn
  principal_arn = each.value.entry.principal_arn

  depends_on = [aws_eks_access_entry.this]
}

########################################
# EKS Identity Provider (OIDC) – opcional
########################################

resource "aws_eks_identity_provider_config" "this" {
  for_each     = var.cluster_identity_providers
  cluster_name = aws_eks_cluster.this.name

  oidc {
    identity_provider_config_name = each.key
    issuer_url                    = coalesce(try(each.value.issuer_url, null), try(aws_eks_cluster.this.identity[0].oidc[0].issuer, null))
    client_id                     = each.value.client_id

    username_claim  = try(each.value.username_claim, null)
    username_prefix = try(each.value.username_prefix, null)
    groups_claim    = try(each.value.groups_claim, null)
    groups_prefix   = try(each.value.groups_prefix, null)
    required_claims = try(each.value.required_claims, null)
  }

  tags = var.tags

  depends_on = [
    aws_eks_cluster.this,
    aws_iam_openid_connect_provider.oidc,
  ]
}

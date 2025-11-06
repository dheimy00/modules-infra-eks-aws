###############################
# outputs.tf – EKS (refatorado)
# Descrições em PT-BR e mais resiliente a counts/condições
###############################

output "cluster_id" {
  description = "ID do cluster EKS"
  value       = aws_eks_cluster.this.id
}

output "cluster_arn" {
  description = "ARN (Amazon Resource Name) do cluster"
  value       = aws_eks_cluster.this.arn
}

output "cluster_name" {
  description = "Nome do cluster EKS"
  value       = aws_eks_cluster.this.name
}

output "cluster_version" {
  description = "Versão do Kubernetes do cluster EKS"
  value       = aws_eks_cluster.this.version
}

output "cluster_endpoint" {
  description = "Endpoint da API (control plane) do EKS"
  value       = aws_eks_cluster.this.endpoint
  sensitive   = true
}

output "cluster_security_group_id" {
  description = "ID do Security Group anexado ao cluster EKS"
  value       = var.create_cluster_security_group ? try(aws_security_group.cluster[0].id, null) : var.cluster_security_group_id
}

output "cluster_certificate_authority_data" {
  description = "Certificado (Base64) necessário para se comunicar com o cluster"
  value       = aws_eks_cluster.this.certificate_authority[0].data
  sensitive   = true
}

output "cluster_iam_role_name" {
  description = "Nome da IAM Role associada ao cluster EKS"
  value       = aws_iam_role.cluster.name
}

output "cluster_iam_role_arn" {
  description = "ARN da IAM Role associada ao cluster EKS"
  value       = aws_iam_role.cluster.arn
}

output "cluster_oidc_issuer_url" {
  description = "URL do emissor OIDC do cluster EKS"
  value       = try(aws_eks_cluster.this.identity[0].oidc[0].issuer, null)
}

output "cluster_oidc_provider_arn" {
  description = "ARN do OIDC Provider (se IRSA habilitado)"
  value       = var.enable_irsa ? try(aws_iam_openid_connect_provider.oidc[0].arn, null) : null
}

output "cluster_platform_version" {
  description = "Platform version do cluster EKS"
  value       = aws_eks_cluster.this.platform_version
}

output "node_security_group_id" {
  description = "ID do Security Group anexado aos nodes"
  value       = var.create_node_security_group ? try(aws_security_group.node[0].id, null) : var.node_security_group_id
}

output "node_iam_role_name" {
  description = "Nome da IAM Role associada aos nodes"
  value       = aws_iam_role.node.name
}

output "node_iam_role_arn" {
  description = "ARN da IAM Role associada aos nodes"
  value       = aws_iam_role.node.arn
}

output "kms_key_id" {
  description = "ARN da chave KMS usada pelo cluster"
  value       = var.create_kms_key ? try(aws_kms_key.eks[0].arn, null) : var.kms_key_id
}

output "kms_key_alias" {
  description = "Alias da chave KMS (se criada pelo módulo)"
  value       = var.create_kms_key ? try(aws_kms_alias.eks[0].name, null) : null
}

output "cloudwatch_log_group_name" {
  description = "Nome do Log Group do CloudWatch criado (se logging habilitado)"
  value       = var.enable_cluster_logging ? try(aws_cloudwatch_log_group.eks_cluster[0].name, null) : null
}

output "ebs_csi_driver_iam_role_arn" {
  description = "ARN da IAM Role do EBS CSI Driver (se IRSA e addon habilitados)"
  value       = contains(keys(var.cluster_addons), "ebs-csi-driver") && var.enable_irsa ? try(aws_iam_role.ebs_csi_driver[0].arn, null) : null
}

output "node_groups" {
  description = "Mapa com atributos dos Node Groups criados (EKS Managed)."
  value = {
    for k, v in aws_eks_node_group.this : k => {
      id                              = v.id
      arn                             = v.arn
      status                          = v.status
      capacity_type                   = v.capacity_type
      disk_size                       = v.disk_size
      instance_types                  = v.instance_types
      node_group_name                 = v.node_group_name
      node_role_arn                   = v.node_role_arn
      release_version                 = v.release_version
      remote_access_security_group_id = try(v.remote_access[0].source_security_group_ids[0], null)
      resources                       = v.resources
      scaling_config                  = v.scaling_config
      subnet_ids                      = v.subnet_ids
      tags                            = v.tags
      taints                          = v.taints
      labels                          = v.labels
    }
  }
}

output "cluster_addons" {
  description = "Mapa com atributos de todos os add-ons criados"
  value = {
    for k, v in aws_eks_addon.this : k => {
      id            = v.id
      arn           = v.arn
      addon_name    = v.addon_name
      addon_version = v.addon_version
      status        = v.status
      created_at    = v.created_at
      modified_at   = v.modified_at
      tags          = v.tags
    }
  }
}

output "cluster_kubernetes_network_config" {
  description = "Bloco de configuração de rede Kubernetes do cluster"
  value       = aws_eks_cluster.this.kubernetes_network_config
}

output "access_entries" {
  description = "Mapa das Access Entries criadas para o cluster (se auth_mode='access-entries')"
  value = {
    for k, v in aws_eks_access_entry.this : k => {
      access_entry_arn  = v.access_entry_arn
      cluster_name      = v.cluster_name
      kubernetes_groups = v.kubernetes_groups
      principal_arn     = v.principal_arn
      type              = v.type
      user_name         = v.user_name
      tags              = v.tags
    }
  }
}

output "cluster_encryption_config" {
  description = "Bloco de configuração de criptografia do cluster"
  value       = aws_eks_cluster.this.encryption_config
}

output "cluster_status" {
  description = "Status atual do cluster EKS"
  value       = aws_eks_cluster.this.status
}

output "cluster_created_at" {
  description = "Data/hora de criação do cluster EKS"
  value       = aws_eks_cluster.this.created_at
}

output "cluster_identity" {
  description = "Informações de identidade do cluster (inclui OIDC, se disponível)"
  value       = aws_eks_cluster.this.identity
}

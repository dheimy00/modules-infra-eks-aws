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



  ########################################
  # aws-auth (opcional, auth_mode = "aws-auth")
  ########################################
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


  ########################################
  # Launch Templates (Nodes)
  ########################################
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
          volume_type           = try(v.disk_type, "gp3")
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

  ########################################
  # Enforce CMK nos nodes (opcional)
  ########################################
  cmk_missing = var.require_cmk_for_nodes && (var.create_kms_key == false) && (var.kms_key_id == null)

  # Escolha do tipo de Load Balancer para Services/Ingress
  lb_kind_normalized = lower(coalesce(var.lb_kind, "alb"))
  use_alb            = local.lb_kind_normalized == "alb"
  use_nlb            = local.lb_kind_normalized == "nlb"

}

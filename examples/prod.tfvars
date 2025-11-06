# Exemplo de produção usando Access Entries (sem aws-auth)
cluster_name    = "eks-prod"
cluster_version = "1.28"

vpc_id     = "vpc-0abcd01234ef56789"
subnet_ids = ["subnet-111111", "subnet-222222", "subnet-333333"]

# Endpoints
cluster_endpoint_private_access = true
cluster_endpoint_public_access  = false

# KMS (CMK já existente)
create_kms_key = false
kms_key_id     = "arn:aws:kms:us-east-1:111122223333:key/00000000-1111-2222-3333-444444444444"

# Modo de auth via Access Entries
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

# Exemplo mínimo (aws-auth, add-ons padrão)
cluster_name    = "eks-dev"
cluster_version = "1.28"

vpc_id = "vpc-0123456789abcdef0"
subnet_ids = [
  "subnet-aaa111",
  "subnet-bbb222"
]

# Endpoints
cluster_endpoint_private_access = true
cluster_endpoint_public_access  = true
cluster_endpoint_public_access_cidrs = [
  "203.0.113.0/24" # restrinja ao seu IP/ bloco corporativo
]

# KMS / Criptografia de secrets
create_kms_key               = true
cluster_encryption_resources = ["secrets"]

# Logs do Control Plane
enable_cluster_logging     = true
cluster_log_retention_days = 7

# IAM / Auth (usa aws-auth)
auth_mode = "aws-auth"

# Node groups
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

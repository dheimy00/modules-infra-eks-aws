# Exemplo LAB com SSH nos nodes e endpoint público aberto (NÃO usar em produção)
cluster_name    = "eks-lab"
cluster_version = "1.28"

vpc_id     = "vpc-0123abcd4567efgh8"
subnet_ids = ["subnet-aaa", "subnet-bbb"]

# Modo de auth via aws-auth (ConfigMap)
auth_mode = "aws-auth"

# Somente LAB: endpoint público liberado 0.0.0.0/0
cluster_endpoint_public_access       = true
cluster_endpoint_private_access      = true
cluster_endpoint_public_access_cidrs = ["0.0.0.0/0"]
allow_public_endpoint_anywhere       = true

# SSH nos nodes
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

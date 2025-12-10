terraform {
  required_version = ">= 1.5"

  required_providers {
    aws        = { source = "hashicorp/aws", version = "~> 4.0" }
    tls        = { source = "hashicorp/tls", version = ">= 4.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = ">= 2.16" }
    helm       = { source = "hashicorp/helm", version = ">= 2.6" }
  }
}

provider "kubernetes" {
  host  = aws_eks_cluster.this.endpoint
  token = data.aws_eks_cluster_auth.this.token

  cluster_ca_certificate = base64decode(
    aws_eks_cluster.this.certificate_authority[0].data
  )
}


# provider "helm" {
#   kubernetes = {
#     host  = aws_eks_cluster.this.endpoint
#     token = data.aws_eks_cluster_auth.this.token
#     cluster_ca_certificate = base64decode(
#       aws_eks_cluster.this.certificate_authority[0].data
#     )
#   }
#   repository_cache       = ""
#   repository_config_path = ""
# }


locals {
  common_tags = merge(
    var.common_tags,
    {
      Project     = var.project
      Environment = var.environment
    }
  )
}

########################
# IAM – Cluster & Nodes
########################

resource "aws_iam_role" "eks_cluster" {
  name = "${var.cluster_name}-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "eks.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "cluster_policy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role" "eks_node" {
  name = "${var.cluster_name}-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "worker_node" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "cni" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "ecr_readonly" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

########################
# Security Groups
########################

resource "aws_security_group" "eks_cluster_sg" {
  name   = "${var.cluster_name}-cluster-sg"
  vpc_id = var.vpc_id

  ingress {
    description = "EKS API access"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

resource "aws_security_group" "eks_nodes_sg" {
  name   = "${var.cluster_name}-nodes-sg"
  vpc_id = var.vpc_id

  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    self      = true
  }

  ingress {
    from_port       = 10250
    to_port         = 10250
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_cluster_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

########################
# EKS Cluster
########################

resource "aws_eks_cluster" "this" {
  name     = var.cluster_name
  role_arn = aws_iam_role.eks_cluster.arn
  version  = var.cluster_version

  vpc_config {
    subnet_ids              = concat(var.private_subnet_ids, var.public_subnet_ids)
    security_group_ids      = [aws_security_group.eks_cluster_sg.id]
    endpoint_public_access  = var.endpoint_public
    endpoint_private_access = var.endpoint_private
    public_access_cidrs     = var.admin_cidrs
  }

  enabled_cluster_log_types = var.cluster_log_types

  tags = local.common_tags
}

data "aws_eks_cluster_auth" "this" {
  name = aws_eks_cluster.this.name
}

data "aws_eks_cluster" "this" {
  name       = aws_eks_cluster.this.name
  depends_on = [aws_eks_cluster.this]
}

########################
# KMS Encryption (optional)
########################

resource "aws_kms_key" "eks" {
  count                   = var.enable_kms ? 1 : 0
  description             = "EKS secrets encryption key"
  deletion_window_in_days = 30
  tags                    = local.common_tags
}

########################
# IRSA – OIDC Integration
########################

data "tls_certificate" "oidc" {
  url = data.aws_eks_cluster.this.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "this" {
  count = var.enable_irsa ? 1 : 0

  url             = data.aws_eks_cluster.this.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.oidc.certificates[0].sha1_fingerprint]

  tags = local.common_tags
}

########################
# Node Group
########################

resource "aws_eks_node_group" "default" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${var.cluster_name}-ng-default"
  node_role_arn   = aws_iam_role.eks_node.arn
  subnet_ids      = concat(var.private_subnet_ids, var.public_subnet_ids)

  scaling_config {
    desired_size = var.node_desired_size
    min_size     = var.node_min_size
    max_size     = var.node_max_size
  }

  instance_types = var.node_instance_types
  capacity_type  = var.node_capacity_type
  disk_size      = var.node_disk_size

  tags = merge(local.common_tags, { Name = "${var.cluster_name}-ng-default" })

  depends_on = [
    aws_iam_role_policy_attachment.worker_node,
    aws_iam_role_policy_attachment.cni,
    aws_iam_role_policy_attachment.ecr_readonly
  ]
}

########################
# Managed Addons
########################

resource "aws_eks_addon" "vpc_cni" {
  addon_name        = "vpc-cni"
  cluster_name      = aws_eks_cluster.this.name
  resolve_conflicts = "OVERWRITE"
}

resource "aws_eks_addon" "coredns" {
  addon_name        = "coredns"
  cluster_name      = aws_eks_cluster.this.name
  resolve_conflicts = "OVERWRITE"
}

resource "aws_eks_addon" "kube_proxy" {
  addon_name        = "kube-proxy"
  cluster_name      = aws_eks_cluster.this.name
  resolve_conflicts = "OVERWRITE"
}

########################
# AWS Load Balancer Controller (IRSA + Helm)
########################

resource "aws_iam_role" "alb_irsa" {
  count = var.enable_irsa ? 1 : 0
  name  = "${var.cluster_name}-alb-irsa"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Federated = aws_iam_openid_connect_provider.this[0].arn },
      Action    = "sts:AssumeRoleWithWebIdentity",
      Condition = {
        StringEquals = {
          "${replace(data.aws_eks_cluster.this.identity[0].oidc[0].issuer, "https://", "")}:sub" = "system:serviceaccount:kube-system:aws-load-balancer-controller"
        }
      }
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_policy" "alb_controller_policy" {
  name   = "${var.cluster_name}-alb-policy"
  policy = file("${path.module}/policies/aws-load-balancer-controller-policy.json")
}

resource "aws_iam_role_policy_attachment" "alb_attach" {
  count      = var.enable_irsa ? 1 : 0
  role       = aws_iam_role.alb_irsa[0].name
  policy_arn = aws_iam_policy.alb_controller_policy.arn
}

resource "kubernetes_service_account_v1" "alb_sa" {
  count = var.enable_irsa ? 1 : 0

  metadata {
    name      = "aws-load-balancer-controller"
    namespace = "kube-system"

    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.alb_irsa[0].arn
    }
  }

  depends_on = [aws_iam_openid_connect_provider.this]
}

# resource "helm_release" "aws_lb_controller" {
#   name       = "aws-load-balancer-controller"
#   namespace  = "kube-system"
#   repository = "https://aws.github.io/eks-charts"
#   chart      = "aws-load-balancer-controller"
#   version    = "1.7.1"

#   set = [{
#     name  = "clusterName"
#     value = var.cluster_name
#     }, {
#     name  = "serviceAccount.create"
#     value = "false"
#     }, {
#     name  = "serviceAccount.name"
#     value = "aws-lb-controller"
#     }
#   ]
# }


########################
# Cluster Autoscaler
########################

resource "aws_iam_role" "autoscaler_irsa" {
  count = var.enable_irsa ? 1 : 0

  name = "${var.cluster_name}-autoscaler-irsa"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Federated = aws_iam_openid_connect_provider.this[0].arn },
      Action    = "sts:AssumeRoleWithWebIdentity",
      Condition = {
        StringEquals = {
          "${replace(data.aws_eks_cluster.this.identity[0].oidc[0].issuer, "https://", "")}:sub" = "system:serviceaccount:kube-system:cluster-autoscaler"
        }
      }
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "autoscaler_policy" {
  count = var.enable_irsa ? 1 : 0

  name = "${var.cluster_name}-autoscaler-policy"
  role = aws_iam_role.autoscaler_irsa[0].id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["autoscaling:*", "ec2:Describe*"],
        Resource = "*"
      }
    ]
  })
}

resource "kubernetes_service_account_v1" "autoscaler_sa" {
  count = var.enable_irsa ? 1 : 0

  metadata {
    name      = "cluster-autoscaler"
    namespace = "kube-system"

    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.autoscaler_irsa[0].arn
    }
  }

  depends_on = [aws_iam_openid_connect_provider.this]
}

# resource "helm_release" "cluster_autoscaler" {
#   name       = "cluster-autoscaler"
#   namespace  = "kube-system"
#   repository = "https://kubernetes.github.io/autoscaler"
#   chart      = "cluster-autoscaler"
#   version    = "9.29.0"

#   set = [{
#     name  = "autoDiscovery.clusterName"
#     value = var.cluster_name
#     },

#     {
#       name  = "awsRegion"
#       value = var.region
#     },

#     {
#       name  = "rbac.serviceAccount.create"
#       value = "false"
#     }
#     ,
#     {
#       name  = "rbac.serviceAccount.name"
#       value = "cluster-autoscaler"
#     }
#   ]
# }


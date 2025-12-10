variable "region" { type = string }
variable "cluster_name" { type = string }
variable "cluster_version" { type = string }

variable "vpc_id" { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "public_subnet_ids" { type = list(string) }

variable "admin_cidrs" { type = list(string) }

variable "node_desired_size" { type = number }
variable "node_min_size" { type = number }
variable "node_max_size" { type = number }
variable "node_instance_types" { type = list(string) }
variable "node_capacity_type" { type = string }
variable "node_disk_size" { type = number }

variable "enable_irsa" { type = bool }
variable "enable_kms" { type = bool }
variable "install_alb_controller" { type = bool }
variable "install_cluster_autoscaler" { type = bool }

variable "endpoint_public" { type = bool }
variable "endpoint_private" { type = bool }
variable "cluster_log_types" {
  type    = list(string)
  default = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
}

variable "environment" { type = string }
variable "project" { type = string }
variable "common_tags" { type = map(string) }

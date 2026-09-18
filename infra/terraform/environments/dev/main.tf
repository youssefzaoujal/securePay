# =============================================================================
# SecurePay - Dev Environment (Terraform)
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Backend S3 (décommenter pour le state distant)
  # backend "s3" {
  #   bucket = "securepay-terraform-state"
  #   key    = "dev/terraform.tfstate"
  #   region = "eu-west-1"
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "SecurePay"
      Environment = "dev"
      ManagedBy   = "Terraform"
    }
  }
}

# --- Variables ---
variable "aws_region" {
  default = "eu-west-1"
}

variable "db_password" {
  sensitive = true
}

variable "keycloak_admin_password" {
  sensitive = true
  default   = "admin"
}

# --- Modules ---
module "vpc" {
  source = "../../modules/vpc"

  project     = "securepay"
  environment = "dev"
  vpc_cidr    = "10.0.0.0/16"
}

module "eks" {
  source = "../../modules/eks"

  project            = "securepay"
  environment        = "dev"
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  public_subnet_ids  = module.vpc.public_subnet_ids
  node_instance_type = "t3.medium"
  node_desired_size  = 2
  node_min_size      = 1
  node_max_size      = 4
}

module "rds" {
  source = "../../modules/rds"

  project                    = "securepay"
  environment                = "dev"
  vpc_id                     = module.vpc.vpc_id
  private_subnet_ids         = module.vpc.private_subnet_ids
  db_password                = var.db_password
  enable_deletion_protection = false
}

# --- Outputs ---
output "vpc_id" { value = module.vpc.vpc_id }
output "eks_cluster_name" { value = module.eks.cluster_name }
output "eks_endpoint" { value = module.eks.cluster_endpoint }
output "rds_endpoint" { value = module.rds.rds_endpoint }
output "redis_endpoint" { value = module.rds.redis_endpoint }
output "nat_gateway_ip" { value = module.vpc.nat_gateway_ip }

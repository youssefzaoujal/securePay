# =============================================================================
# VPC Module - SecurePay
# =============================================================================

variable "project" { type = string }
variable "environment" { type = string }
variable "vpc_cidr" { type = string }

locals {
  azs = ["${var.project}-${var.environment}-az-a", "${var.project}-${var.environment}-az-b"]
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.project}-${var.environment}-vpc"
    Project     = var.project
    Environment = var.environment
  }
}

# --- Public Subnets ---
resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 10)
  availability_zone       = "${var.project}-${var.environment}-az-a"
  map_public_ip_on_launch = true

  tags = {
    Name        = "${var.project}-public-a"
    Tier        = "public"
    Environment = var.environment
  }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 20)
  availability_zone       = "${var.project}-${var.environment}-az-b"
  map_public_ip_on_launch = true

  tags = {
    Name        = "${var.project}-public-b"
    Tier        = "public"
    Environment = var.environment
  }
}

# --- Private Subnets (EKS, RDS, ElastiCache) ---
resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 100)
  availability_zone = "${var.project}-${var.environment}-az-a"

  tags = {
    Name        = "${var.project}-private-a"
    Tier        = "private"
    Environment = var.environment
    "kubernetes.io/role/internal-elb" = "1"
  }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 110)
  availability_zone = "${var.project}-${var.environment}-az-b"

  tags = {
    Name        = "${var.project}-private-b"
    Tier        = "private"
    Environment = var.environment
    "kubernetes.io/role/internal-elb" = "1"
  }
}

# --- Internet Gateway ---
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "${var.project}-igw"
  }
}

# --- NAT Gateway (pour les pods EKS dans les subnets privés) ---
resource "aws_eip" "nat" {
  domain = "vpc"
  tags = { Name = "${var.project}-nat-eip" }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_a.id
  tags = { Name = "${var.project}-nat" }

  depends_on = [aws_internet_gateway.main]
}

# --- Route Tables ---
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${var.project}-public-rt" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = { Name = "${var.project}-private-rt" }
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private.id
}

# --- Outputs ---
output "vpc_id" { value = aws_vpc.main.id }
output "public_subnet_ids" { value = [aws_subnet.public_a.id, aws_subnet.public_b.id] }
output "private_subnet_ids" { value = [aws_subnet.private_a.id, aws_subnet.private_b.id] }
output "nat_gateway_ip" { value = aws_eip.nat.public_ip }

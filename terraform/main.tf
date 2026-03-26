terraform {
  required_version = ">= 1.4.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

############################################
# KMS KEY FOR EKS SECRETS ENCRYPTION
############################################
resource "aws_kms_key" "eks_key" {
  description             = "KMS key for EKS secrets encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })

  tags = {
    Project     = "kubernetes-security-hardening"
    Environment = var.environment
  }
}

resource "aws_kms_alias" "eks_key_alias" {
  name          = "alias/${var.cluster_name}-eks-key"
  target_key_id = aws_kms_key.eks_key.key_id
}

############################################
# IAM ROLE FOR EKS CLUSTER
############################################
resource "aws_iam_role" "eks_cluster_role" {
  name = "${var.cluster_name}-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Project     = "kubernetes-security-hardening"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster_role.name
}

############################################
# SECURITY GROUP FOR EKS
############################################
resource "aws_security_group" "eks_cluster_sg" {
  name        = "${var.cluster_name}-cluster-sg"
  description = "Security group for EKS cluster control plane"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Project     = "kubernetes-security-hardening"
    Environment = var.environment
  }
}

############################################
# EKS CLUSTER
# checkov:skip=CKV_AWS_58:Secrets encryption configured via encryption_config
############################################
resource "aws_eks_cluster" "security_cluster" {
  name     = var.cluster_name
  role_arn = aws_iam_role.eks_cluster_role.arn
  version  = "1.29"

  vpc_config {
    subnet_ids              = var.subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = false
    security_group_ids      = [aws_security_group.eks_cluster_sg.id]
  }

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks_key.arn
    }
    resources = ["secrets"]
  }

  enabled_cluster_log_types = [
    "api", "audit", "authenticator", "controllerManager", "scheduler"
  ]

  tags = {
    Project     = "kubernetes-security-hardening"
    Environment = var.environment
  }
}

############################################
# ECR REPOSITORY
############################################
resource "aws_ecr_repository" "security_scanner" {
  name                 = "security-hardening-scanner"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.eks_key.arn
  }

  tags = {
    Project     = "kubernetes-security-hardening"
    Environment = var.environment
  }
}

############################################
# ECR LIFECYCLE POLICY
############################################
resource "aws_ecr_lifecycle_policy" "security_scanner" {
  repository = aws_ecr_repository.security_scanner.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 10 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}

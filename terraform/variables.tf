variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}
variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
  default     = "security-hardening-cluster"
}
variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "dev"
}
variable "vpc_id" {
  description = "VPC ID for EKS cluster"
  type        = string
}
variable "subnet_ids" {
  description = "Subnet IDs for EKS cluster"
  type        = list(string)
}

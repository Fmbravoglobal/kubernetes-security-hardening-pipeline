output "cluster_name" {
  value = aws_eks_cluster.security_cluster.name
}
output "cluster_endpoint" {
  value = aws_eks_cluster.security_cluster.endpoint
}
output "ecr_repository_url" {
  value = aws_ecr_repository.security_scanner.repository_url
}

output "vpc_id" {
  description = "ID of the platform VPC."
  value       = aws_vpc.platform.id
}

output "db_endpoint" {
  description = "Hostname/address of the managed Postgres/AGE datastore. Used to construct DATABASE_URL / ADMIN_DATABASE_URL at runtime — the DSN is never constructed in HCL."
  value       = aws_db_instance.platform_postgres_age.address
}

output "db_port" {
  description = "Port of the managed Postgres/AGE datastore."
  value       = aws_db_instance.platform_postgres_age.port
}

output "api_service_port" {
  description = "Port the API container exposes (default 8000). Matches var.api_container_port."
  value       = var.api_container_port
}

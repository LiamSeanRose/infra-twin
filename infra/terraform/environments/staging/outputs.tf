output "vpc_id" {
  description = "ID of the staging platform VPC."
  value       = module.platform.vpc_id
}

output "db_endpoint" {
  description = "Hostname of the staging Postgres/AGE datastore."
  value       = module.platform.db_endpoint
}

output "db_port" {
  description = "Port of the staging Postgres/AGE datastore."
  value       = module.platform.db_port
}

output "api_service_port" {
  description = "Port the staging API service exposes."
  value       = module.platform.api_service_port
}

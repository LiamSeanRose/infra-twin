output "vpc_id" {
  description = "ID of the production platform VPC."
  value       = module.platform.vpc_id
}

output "db_endpoint" {
  description = "Hostname of the production Postgres/AGE datastore."
  value       = module.platform.db_endpoint
}

output "db_port" {
  description = "Port of the production Postgres/AGE datastore."
  value       = module.platform.db_port
}

output "api_service_port" {
  description = "Port the production API service exposes."
  value       = module.platform.api_service_port
}

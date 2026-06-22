# infra/terraform — Platform Infrastructure

This tree provisions the infra-twin platform's own infrastructure (plan §23, roadmap #31b-ii):
a VPC/network, a managed Postgres+AGE datastore, and a compute service running the API container.

This is NOT the customer-onboarding IaC. The customer-onboarding read-only role CloudFormation
template lives at `infra/onboarding/aws/infra-twin-readonly-role.yaml` and is separate.

## Layout

```
modules/platform/      Reusable module: VPC, managed Postgres/AGE, ECS compute service
environments/staging/  Staging environment: remote S3 backend + module call
environments/prod/     Production environment: remote S3 backend (distinct key) + module call
```

## State and locking

Each environment maintains its own remote Terraform state in S3 with DynamoDB-based state
locking. The bucket and lock table are declared as code placeholders; point them at real
resources before running `terraform apply`.

- Staging state key: `platform/staging/terraform.tfstate`
- Prod state key: `platform/prod/terraform.tfstate`
- Lock table: `infra-twin-tflock` (DynamoDB)

## Deploy-time variable injection

Secrets (DB password, etc.) are NEVER in `.tf` files or `.tfvars` files committed to VCS.
The DB password is referenced only as a Secrets Manager ARN (`db_password_secret_arn`).
The API image tag (`api_image_tag`) is injected at deploy time from the CI pipeline — it
should be set to the git SHA of the commit being deployed.

Copy `terraform.tfvars.example` to `terraform.tfvars` in the target environment directory,
fill in the non-secret values, and supply secret values via environment variables or a
secrets manager at deploy time. Real `.tfvars` files are `.gitignore`d.

## Usage

```sh
cd infra/terraform/environments/staging
terraform init
terraform plan -var-file=terraform.tfvars
terraform apply -var-file=terraform.tfvars
```

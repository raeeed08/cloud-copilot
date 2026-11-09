# Cloud Copilot lab (Azure)

```bash
az login                                   # an account with Owner (or Contributor + User Access Administrator)
cd infra/terraform/lab-azure
terraform init
terraform apply -var subscription_id=$(az account show --query id -o tsv)
terraform output connect_in_cloud_copilot
terraform output -raw scanner_client_secret
```
Dashboard → **Accounts** → Azure → **Service principal**: tenant ID, client ID, client secret, subscription.
Role assignments can take a minute or two to propagate. If "Test connection" fails, retry.

Fix: `terraform apply -var subscription_id=... -var secure=true`, then re-scan.
Clean up: `terraform destroy -var subscription_id=...`.

| Resource | Insecure | Rule(s) |
|---|---|---|
| Storage account | anonymous blob access allowed, TLS 1.0, all networks | AZ-STOR-001/003/005 (+004) |
| NSG | RDP 3389 from Internet | AZ-NSG-001 |
| Public IP | Standard, unassociated | AZ-COST-001 |
| Key Vault | access policies, all networks, no purge protection | AZ-KV-001/002/003 |
| Subscription | (untouched) diagnostic settings, Defender plans | AZ-MON-001/002, AZ-DEF-001 |

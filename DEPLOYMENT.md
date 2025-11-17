# Deployment Guide

Complete step-by-step guide for deploying the Qualys Cloud Run Scanner.

## Prerequisites

Before you begin, ensure you have:

1. **GCP Account** with billing enabled
2. **GCP Project** created and selected
3. **gcloud CLI** installed and authenticated
4. **Terraform** >= 1.0 installed
5. **Qualys Subscription** with Container Security enabled
6. **Qualys API Access Token** from your Qualys portal

## Step-by-Step Deployment

### 1. Authenticate with GCP

```bash
# Login to GCP
gcloud auth login

# Set your project
gcloud config set project YOUR_PROJECT_ID

# Enable application default credentials for Terraform
gcloud auth application-default login
```

### 2. Clone the Repository

```bash
git clone https://github.com/nelssec/qualys-cloudrun.git
cd qualys-cloudrun
```

### 3. Prepare Terraform Configuration

```bash
cd infrastructure

# Copy the example variables file
cp terraform.tfvars.example terraform.tfvars

# Edit with your values
nano terraform.tfvars
```

Update `terraform.tfvars` with your configuration:

```hcl
project_id = "your-gcp-project-id"
region     = "us-central1"
qualys_pod = "qualysapi.qualys.com"  # Or your specific Qualys POD

# Optional customizations
# firestore_location          = "nam5"
# qscanner_image              = "qualys/qscanner:latest"
# scan_cache_hours            = 24
# notify_severity_threshold   = "HIGH"
```

### 4. Deploy Infrastructure with Terraform

```bash
# Initialize Terraform
terraform init

# Review the deployment plan
terraform plan

# Deploy (this will take 5-10 minutes)
terraform apply

# Type 'yes' to confirm
```

### 5. Configure Qualys Credentials

After Terraform completes, add your Qualys access token to Secret Manager:

```bash
# Replace YOUR_QUALYS_TOKEN with your actual token
echo -n "YOUR_QUALYS_TOKEN" | gcloud secrets versions add qualys-access-token --data-file=-
```

To get your Qualys access token:
1. Log in to your Qualys portal
2. Navigate to **Apps** → **API & Integrations**
3. Create a new API token with Container Security permissions
4. Copy the token value

### 6. Verify Deployment

Check that all components are deployed:

```bash
# Check Cloud Function
gcloud functions describe qualys-cloudrun-scanner --region=us-central1 --gen2

# Check Pub/Sub topic
gcloud pubsub topics describe cloudrun-deployment-events

# Check Cloud Storage bucket
gcloud storage ls | grep qualys-scan-results

# Check Secret Manager
gcloud secrets describe qualys-access-token
```

### 7. Test the Scanner

Deploy a test Cloud Run service to trigger a scan:

```bash
# Deploy a simple Cloud Run service
gcloud run deploy test-app \
  --image=gcr.io/cloudrun/hello \
  --region=us-central1 \
  --allow-unauthenticated

# Wait a few moments, then check the function logs
gcloud functions logs read qualys-cloudrun-scanner \
  --region=us-central1 \
  --limit=50
```

You should see logs showing:
- Event received
- Image being scanned
- Cloud Run Job created
- Scan results saved

### 8. View Scan Results

```bash
# List scan results in Cloud Storage
gcloud storage ls gs://$(terraform output -raw scan_results_bucket)/

# Or view in the console
echo "View results at: https://console.cloud.google.com/storage/browser/$(terraform output -raw scan_results_bucket)"
```

## Multi-Region Deployment

To deploy in multiple regions:

1. Copy the infrastructure directory:
```bash
cp -r infrastructure infrastructure-europe
cd infrastructure-europe
```

2. Update `terraform.tfvars`:
```hcl
region = "europe-west1"
```

3. Deploy:
```bash
terraform init
terraform apply
```

## Multi-Project Deployment

For scanning Cloud Run services across multiple projects:

### Option 1: Centralized Scanner (Recommended)

Deploy the scanner in a central "security" project:

1. Deploy infrastructure in the security project (as above)

2. In each target project, configure a log sink to the central Pub/Sub topic:

```bash
# Run this in each target project
TARGET_PROJECT="target-project-id"
SECURITY_PROJECT="security-project-id"

gcloud logging sinks create cloudrun-to-security \
  --project=${TARGET_PROJECT} \
  --log-filter='resource.type="cloud_run_revision" protoPayload.methodName=~"google.cloud.run.v2.Services.(Create|Update)Service"' \
  --destination=pubsub.googleapis.com/projects/${SECURITY_PROJECT}/topics/cloudrun-deployment-events

# Grant the sink service account permission to publish
SINK_SA=$(gcloud logging sinks describe cloudrun-to-security --project=${TARGET_PROJECT} --format='value(writerIdentity)')

gcloud pubsub topics add-iam-policy-binding cloudrun-deployment-events \
  --project=${SECURITY_PROJECT} \
  --member=${SINK_SA} \
  --role=roles/pubsub.publisher
```

3. Grant the scanner function permissions in target projects:

```bash
# Run this in each target project
TARGET_PROJECT="target-project-id"
SECURITY_PROJECT="security-project-id"

SCANNER_SA=$(cd infrastructure && terraform output -raw scanner_service_account)

gcloud projects add-iam-policy-binding ${TARGET_PROJECT} \
  --member="serviceAccount:${SCANNER_SA}" \
  --role=roles/run.admin
```

### Option 2: Per-Project Scanner

Deploy the scanner infrastructure in each project independently.

## Upgrading

To upgrade to a newer version:

```bash
# Pull latest code
git pull origin main

# Review changes
cd infrastructure
terraform plan

# Apply updates
terraform apply
```

## Uninstalling

To remove all infrastructure:

```bash
cd infrastructure

# Destroy all resources
terraform destroy

# Type 'yes' to confirm
```

**Warning**: This will delete:
- Cloud Function
- Cloud Run Jobs (active scans)
- Cloud Storage buckets (including scan results)
- Firestore data
- Pub/Sub topics
- Service accounts
- Secrets

To preserve scan results, first backup the Cloud Storage bucket:

```bash
# Backup results before destroying
gcloud storage cp -r gs://$(terraform output -raw scan_results_bucket)/ ./backup/
```

## Troubleshooting Deployment

### Terraform Errors

**API not enabled:**
```
Error: Error creating function: googleapi: Error 403: ...
```

Solution: Wait a few minutes after `terraform apply` for APIs to fully enable, then run `terraform apply` again.

**Quota exceeded:**
```
Error: Error creating Cloud Run job: Quota exceeded
```

Solution: Request quota increase in GCP Console → IAM & Admin → Quotas.

### Permission Errors

**Service account lacks permissions:**
```
Error: Error creating job: Permission denied
```

Solution: Ensure your user account has necessary roles:
```bash
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="user:YOUR_EMAIL" \
  --role=roles/owner
```

### Function Deployment Fails

**Function source too large:**

Solution: The function source is zipped automatically. If issues occur, manually clean:
```bash
cd cloud_function
rm -rf __pycache__
cd ../infrastructure
terraform apply
```

## Next Steps

After successful deployment:

1. **Configure Alerting**: Set up notifications for high-severity findings
2. **Review Results**: Check initial scan results in Cloud Storage
3. **Tune Cache Settings**: Adjust `scan_cache_hours` based on your needs
4. **Monitor Costs**: Review Cloud Billing for actual usage costs
5. **Set Up Dashboards**: Create Cloud Monitoring dashboards for scan metrics

## Support

If you encounter issues:

1. Check the [Troubleshooting](README.md#troubleshooting) section in README
2. Review Cloud Function logs
3. Open an issue on GitHub
4. Contact Qualys support for scanner-specific issues

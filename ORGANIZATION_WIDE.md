# Organization-Wide Deployment

Deploy the scanner once to monitor all Cloud Run deployments across your entire GCP organization.

## Architecture

Instead of deploying the scanner in each project, deploy it once in a central security project. All Cloud Audit Logs from across the organization route to a single Pub/Sub topic in that project.

```
Project A: Cloud Run deployment
Project B: Cloud Run deployment
Project C: Cloud Run deployment
          ↓ (all audit logs)
  Organization Log Sink
          ↓
Central Security Project
    - Pub/Sub Topic
    - Cloud Function
    - Cloud Run Jobs
    - Storage
```

## Prerequisites

- Organization-level access (roles/logging.configWriter at org level)
- A dedicated security/monitoring project
- Permissions to create organization-level log sinks

## Deployment Steps

### 1. Create Security Project

```bash
# Create a dedicated project for security scanning
gcloud projects create your-security-project --organization=YOUR_ORG_ID
gcloud config set project your-security-project

# Enable billing
gcloud billing projects link your-security-project --billing-account=YOUR_BILLING_ACCOUNT
```

### 2. Deploy Infrastructure in Security Project

```bash
cd infrastructure
cp terraform.tfvars.example terraform.tfvars

# Edit terraform.tfvars
nano terraform.tfvars
```

Update with your security project details:

```hcl
project_id = "your-security-project"
region     = "us-central1"
qualys_pod = "qualysapi.qualys.com"
```

Deploy:

```bash
terraform init
terraform apply
```

### 3. Configure Qualys Token

```bash
echo -n "YOUR_QUALYS_TOKEN" | gcloud secrets versions add qualys-access-token --data-file=-
```

### 4. Create Organization-Level Log Sink

This aggregates Cloud Run events from all projects in your organization.

```bash
# Get your organization ID
ORG_ID=$(gcloud organizations list --format="value(name)")

# Get the Pub/Sub topic from terraform
PUBSUB_TOPIC=$(cd infrastructure && terraform output -raw pubsub_topic)
SECURITY_PROJECT=$(cd infrastructure && terraform output -raw project_id)

# Create organization-level log sink
gcloud logging sinks create cloudrun-org-scanner \
  --organization=${ORG_ID} \
  --log-filter='resource.type="cloud_run_revision"
protoPayload.methodName=~"google.cloud.run.v2.Services.(Create|Update)Service"' \
  --destination=pubsub.googleapis.com/projects/${SECURITY_PROJECT}/topics/${PUBSUB_TOPIC} \
  --include-children
```

The `--include-children` flag ensures logs from all projects under the organization are captured.

### 5. Grant Permissions to Log Sink Service Account

```bash
# Get the service account created by the log sink
SINK_SA=$(gcloud logging sinks describe cloudrun-org-scanner \
  --organization=${ORG_ID} \
  --format="value(writerIdentity)")

# Grant permission to publish to Pub/Sub topic
gcloud pubsub topics add-iam-policy-binding ${PUBSUB_TOPIC} \
  --project=${SECURITY_PROJECT} \
  --member="${SINK_SA}" \
  --role=roles/pubsub.publisher
```

### 6. Grant Scanner Cross-Project Permissions

The scanner needs permissions to create Cloud Run Jobs in the security project and potentially access images from other projects' registries.

```bash
# Get scanner service account
SCANNER_SA=$(cd infrastructure && terraform output -raw scanner_service_account)

# If you need to scan images from other project registries, grant read access
# This is optional - only needed if scanning private images from other projects
gcloud organizations add-iam-policy-binding ${ORG_ID} \
  --member="serviceAccount:${SCANNER_SA}" \
  --role=roles/artifactregistry.reader \
  --condition=None
```

### 7. Test Organization-Wide Scanning

Deploy a test Cloud Run service in any project in your organization:

```bash
# Switch to any project
gcloud config set project some-other-project

# Deploy a service
gcloud run deploy test-app \
  --image=gcr.io/cloudrun/hello \
  --region=us-central1 \
  --allow-unauthenticated

# Switch back to security project to check logs
gcloud config set project your-security-project

# View function logs
gcloud functions logs read qualys-cloudrun-scanner \
  --region=us-central1 \
  --limit=50
```

You should see the scan triggered even though the Cloud Run service was deployed in a different project.

## Folder-Level Deployment

If you don't want organization-wide scanning, you can scope to specific folders:

```bash
FOLDER_ID="123456789"

gcloud logging sinks create cloudrun-folder-scanner \
  --folder=${FOLDER_ID} \
  --log-filter='resource.type="cloud_run_revision"
protoPayload.methodName=~"google.cloud.run.v2.Services.(Create|Update)Service"' \
  --destination=pubsub.googleapis.com/projects/${SECURITY_PROJECT}/topics/${PUBSUB_TOPIC} \
  --include-children
```

## Monitoring Organization-Wide Scans

### Query Scans Across All Projects

```bash
# List all scanned images
gcloud firestore export gs://backup-bucket/export \
  --collection-ids=scan_metadata \
  --project=your-security-project

# Or query programmatically
```

Python example:

```python
from google.cloud import firestore

db = firestore.Client(project='your-security-project')

# Get all scans with critical vulnerabilities
scans = db.collection('scan_metadata') \
  .where('vuln_critical', '>', 0) \
  .order_by('timestamp_str', direction=firestore.Query.DESCENDING) \
  .limit(100) \
  .stream()

for scan in scans:
    data = scan.to_dict()
    print(f"{data['project_id']}/{data['service_name']}: {data['image']} - {data['vuln_critical']} critical")
```

### View Scan Results by Project

Results are automatically tagged with source project information from the audit log.

## Cost Considerations

Organization-wide deployment costs are based on the number of Cloud Run deployments across all projects:

- 1000 deployments/month across 50 projects: approximately $30/month
- Includes Cloud Function invocations, Cloud Run Job executions, storage, and Firestore operations

Log ingestion for audit logs is free, but there are quotas on log sink throughput.

## Permissions Summary

Required roles:

- Organization level:
  - roles/logging.configWriter (to create organization log sink)
  - roles/iam.organizationRoleAdmin (to grant scanner permissions)

- Security project:
  - roles/owner or equivalent (to deploy infrastructure)

- Scanner service account gets:
  - roles/run.admin (to create scan jobs)
  - roles/storage.objectAdmin (to store results)
  - roles/datastore.user (to write metadata)
  - roles/secretmanager.secretAccessor (to read Qualys token)

## Troubleshooting

### Logs Not Arriving from Other Projects

Check the organization sink status:

```bash
gcloud logging sinks describe cloudrun-org-scanner --organization=${ORG_ID}
```

Verify the filter is correct:

```bash
# Test the filter in a specific project
gcloud logging read 'resource.type="cloud_run_revision"
protoPayload.methodName=~"google.cloud.run.v2.Services.CreateService"' \
  --project=some-project \
  --limit=5
```

### Permission Denied Errors

Ensure the log sink service account has pubsub.publisher:

```bash
gcloud pubsub topics get-iam-policy ${PUBSUB_TOPIC} --project=${SECURITY_PROJECT}
```

### Scanner Can't Access Images

If scanning private images from other projects:

```bash
# Grant scanner access to specific Artifact Registry
gcloud artifacts repositories add-iam-policy-binding REPO_NAME \
  --project=image-project \
  --location=us-central1 \
  --member="serviceAccount:${SCANNER_SA}" \
  --role=roles/artifactregistry.reader
```

## Migrating from Per-Project to Organization-Wide

If you already have per-project deployments:

1. Deploy the centralized scanner in security project (above steps)
2. Delete per-project Terraform deployments:
   ```bash
   cd each-project/infrastructure
   terraform destroy
   ```
3. Keep scan history by copying Cloud Storage buckets:
   ```bash
   gsutil -m cp -r gs://old-project-scan-results/* gs://security-project-scan-results/
   ```

## Alternative: Shared VPC Deployment

For organizations using Shared VPC, you can deploy the scanner in the host project and have it accessible from service projects. This requires additional VPC configuration and is beyond the scope of this guide.

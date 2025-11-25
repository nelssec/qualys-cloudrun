# Qualys Container Scanner for Google Cloud Run

Automated vulnerability scanning for container images deployed to Google Cloud Run. This solution provides event-driven security scanning using Qualys qscanner, triggered automatically when Cloud Run services are created or updated.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Security Features](#security-features)
- [Prerequisites](#prerequisites)
- [Deployment](#deployment)
  - [Single Project](#single-project-deployment)
  - [Multi-Region](#multi-region-deployment)
  - [Organization-Wide](#organization-wide-deployment)
- [Configuration Reference](#configuration-reference)
- [Operations](#operations)
- [Troubleshooting](#troubleshooting)
- [Cost Estimation](#cost-estimation)

## Overview

This solution implements automated container image scanning for Cloud Run deployments. When a Cloud Run service is deployed or updated, the system:

1. Captures the deployment event via Cloud Audit Logs
2. Routes the event through Pub/Sub to a Cloud Function
3. Extracts container image references from the service definition
4. Spawns an ephemeral Cloud Run Job running Qualys qscanner
5. Stores vulnerability and compliance data in Cloud Storage and Firestore
6. Optionally triggers alerts for high-severity findings
7. Automatically cleans up the scanner job after completion

The scanner uses the official `qualys/qscanner` Docker image and authenticates via Secret Manager, ensuring credentials are never exposed in logs or job definitions.

## Architecture

```
                                    Single Project
    +------------------------------------------------------------------+
    |                                                                  |
    |   Cloud Run Service Deployment                                   |
    |            |                                                     |
    |            v                                                     |
    |   Cloud Audit Logs                                               |
    |            |                                                     |
    |            v                                                     |
    |   Logging Sink -----> Pub/Sub Topic                              |
    |                            |                                     |
    |                            v                                     |
    |                    Cloud Function (Gen2)                         |
    |                            |                                     |
    |                            v                                     |
    |                    Cloud Run Job (qscanner)                      |
    |                            |                                     |
    |                            v                                     |
    |            +---------------+---------------+                     |
    |            |                               |                     |
    |            v                               v                     |
    |    Cloud Storage                      Firestore                  |
    |    (Detailed JSON)                 (Queryable Metadata)          |
    |                                                                  |
    +------------------------------------------------------------------+
```

### Components

| Component | Purpose |
|-----------|---------|
| Cloud Function (Gen2) | Event processor that orchestrates scans |
| Cloud Run Jobs | Ephemeral containers running Qualys qscanner |
| Cloud Storage | Stores detailed scan results as JSON files |
| Firestore | Indexes scan metadata for querying and dashboards |
| Secret Manager | Securely stores Qualys API credentials |
| Pub/Sub | Event routing from Cloud Audit Logs |
| Logging Sink | Filters and routes Cloud Run deployment events |

### Event Flow

1. **Audit Log Generation**: Cloud Run generates audit logs for `CreateService` and `UpdateService` operations
2. **Log Sink Filtering**: The logging sink filters for Cloud Run revision events and forwards to Pub/Sub
3. **Event Processing**: The Cloud Function receives CloudEvents via Pub/Sub trigger
4. **Image Extraction**: Container images are extracted from the service template in the audit log
5. **Deduplication**: Recent scans are checked in Firestore to avoid duplicate scanning
6. **Job Creation**: A Cloud Run Job is created with the qscanner container
7. **Scan Execution**: qscanner analyzes the image against Qualys vulnerability database
8. **Result Storage**: Results are stored in Cloud Storage (full JSON) and Firestore (metadata)
9. **Cleanup**: The scanner job is deleted after completion

## Security Features

This solution implements security hardening for enterprise deployments:

### IAM and Access Control

- **Least Privilege**: Service accounts are granted minimum required permissions
  - Cloud Function SA: `storage.objectUser`, `datastore.user`, `logging.logWriter`, `run.developer`
  - Cloud Run Jobs SA: `logging.logWriter`, `secretmanager.secretAccessor` (secret-level only)
- **Secret-Level IAM**: Qualys token access is granted at the individual secret level, not project-level
- **No Project-Level Admin Roles**: Uses `run.developer` instead of `run.admin`

### Secret Management

- Qualys API token stored in Secret Manager
- Cloud Run Jobs access secrets via Secret Manager references, not environment variables
- Credentials never appear in job definitions, logs, or environment listings

### Input Validation

- Container image names validated against OCI specification patterns
- Shell injection characters blocked: `$`, backtick, `;`, `&`, `|`, `>`, `<`, `\n`, `\0`, `\`
- Maximum length limits to prevent DoS attacks
- Custom tag values sanitized before use in commands
- All command arguments use `shlex.quote()` for safe shell execution

### Storage Security

- Cloud Storage buckets configured with `public_access_prevention = "enforced"`
- Uniform bucket-level access enabled (no legacy ACLs)
- Soft delete policy for accidental deletion recovery
- Versioning enabled for audit trail

### Network Security

- Cloud Function ingress restricted to internal traffic only
- Optional VPC connector support for private networking
- VPC Service Controls compatible

## Prerequisites

- Google Cloud Platform project with billing enabled
- Terraform >= 1.0
- Qualys subscription with Container Security module and API access
- `gcloud` CLI installed and authenticated
- Required APIs will be enabled automatically by Terraform

### Required IAM Roles for Deployment

The user or service account deploying the infrastructure needs:

- `roles/owner` or equivalent permissions on the target project, OR
- Individual roles: `roles/iam.serviceAccountAdmin`, `roles/cloudfunctions.admin`, `roles/run.admin`, `roles/storage.admin`, `roles/pubsub.admin`, `roles/logging.configWriter`, `roles/secretmanager.admin`, `roles/datastore.owner`

## Deployment

### Single Project Deployment

Deploy the scanner to monitor Cloud Run services within a single GCP project.

#### Step 1: Clone Repository

```bash
git clone https://github.com/nelssec/qualys-cloudrun.git
cd qualys-cloudrun/infrastructure
```

#### Step 2: Configure Variables

```bash
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with your values:

```hcl
project_id = "your-project-id"
region     = "us-central1"
qualys_pod = "US02"  # Your Qualys POD identifier

# Optional: Security hardening
# qscanner_image              = "qualys/qscanner:1.25"  # Pin specific version
# scan_results_retention_days = 90
# enable_vpc_connector        = true
# vpc_connector_name          = "projects/PROJECT/locations/REGION/connectors/NAME"
```

#### Step 3: Deploy Infrastructure

```bash
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

#### Step 4: Configure Qualys Credentials

```bash
# Add your Qualys API token to Secret Manager
echo -n "YOUR_QUALYS_ACCESS_TOKEN" | \
  gcloud secrets versions add qualys-access-token --data-file=-
```

To obtain your Qualys access token:

1. Log in to the Qualys Console
2. Navigate to Administration then Users
3. Generate an API token for your user account
4. Ensure the account has Container Security permissions

#### Step 5: Verify Deployment

Deploy a test Cloud Run service to trigger scanning:

```bash
gcloud run deploy test-scanner \
  --image=gcr.io/cloudrun/hello \
  --region=us-central1 \
  --allow-unauthenticated

# View scanner function logs
gcloud functions logs read qualys-cloudrun-scanner \
  --region=us-central1 \
  --limit=50
```

### Multi-Region Deployment

Deploy scanners to multiple regions to reduce latency and comply with data residency requirements.

#### Option A: Regional Terraform Workspaces

```bash
cd infrastructure

# Deploy to us-central1
terraform workspace new us-central1
terraform apply -var="region=us-central1"

# Deploy to europe-west1
terraform workspace new europe-west1
terraform apply -var="region=europe-west1" -var="firestore_location=eur3"

# Deploy to asia-northeast1
terraform workspace new asia-northeast1
terraform apply -var="region=asia-northeast1" -var="firestore_location=asia1"
```

#### Option B: Separate State Files

```bash
# US deployment
cd infrastructure
terraform init -backend-config="prefix=terraform/state/us-central1"
terraform apply -var="region=us-central1"

# EU deployment
cd ../infrastructure-eu
terraform init -backend-config="prefix=terraform/state/europe-west1"
terraform apply -var="region=europe-west1" -var="firestore_location=eur3"
```

#### Regional Considerations

- Each region maintains independent Cloud Function, Pub/Sub topic, and log sink
- Cloud Storage bucket location should match the function region
- Firestore location must be a multi-region: `nam5` (North America), `eur3` (Europe), `asia1` (Asia)
- Qualys POD should match regional requirements for data residency

### Organization-Wide Deployment

Deploy a single scanner instance to monitor all Cloud Run deployments across your entire GCP organization.

#### Architecture

```
    Project A                Project B                Project C
    (Cloud Run)              (Cloud Run)              (Cloud Run)
         |                        |                        |
         +------------------------+------------------------+
                                  |
                                  v
                    Organization-Level Log Sink
                                  |
                                  v
                    +---------------------------+
                    |   Security Project        |
                    |   - Pub/Sub Topic         |
                    |   - Cloud Function        |
                    |   - Cloud Run Jobs        |
                    |   - Cloud Storage         |
                    |   - Firestore             |
                    +---------------------------+
```

#### Step 1: Create Security Project

```bash
# Create dedicated security project
gcloud projects create security-scanner-prod \
  --organization=YOUR_ORG_ID

# Link billing
gcloud billing projects link security-scanner-prod \
  --billing-account=YOUR_BILLING_ACCOUNT

gcloud config set project security-scanner-prod
```

#### Step 2: Deploy Infrastructure

Deploy the scanner infrastructure in the security project using the standard deployment steps above.

#### Step 3: Create Organization Log Sink

```bash
# Get organization ID
ORG_ID=$(gcloud organizations list --format="value(ID)")

# Get Pub/Sub topic from Terraform output
SECURITY_PROJECT="security-scanner-prod"
PUBSUB_TOPIC="cloudrun-deployment-events"

# Create organization-level log sink
gcloud logging sinks create cloudrun-org-scanner \
  pubsub.googleapis.com/projects/${SECURITY_PROJECT}/topics/${PUBSUB_TOPIC} \
  --organization=${ORG_ID} \
  --include-children \
  --log-filter='resource.type="cloud_run_revision"
protoPayload.methodName=~"google.cloud.run.v2.Services.(Create|Update)Service"'
```

#### Step 4: Grant Log Sink Permissions

```bash
# Get the log sink writer identity
SINK_SA=$(gcloud logging sinks describe cloudrun-org-scanner \
  --organization=${ORG_ID} \
  --format="value(writerIdentity)")

# Grant publish permission to Pub/Sub topic
gcloud pubsub topics add-iam-policy-binding ${PUBSUB_TOPIC} \
  --project=${SECURITY_PROJECT} \
  --member="${SINK_SA}" \
  --role=roles/pubsub.publisher
```

#### Step 5: Grant Cross-Project Image Access (Optional)

If scanning private images from Artifact Registry in other projects:

```bash
SCANNER_SA=$(terraform output -raw scanner_service_account)

# Organization-wide Artifact Registry read access
gcloud organizations add-iam-policy-binding ${ORG_ID} \
  --member="serviceAccount:${SCANNER_SA}" \
  --role=roles/artifactregistry.reader \
  --condition=None
```

#### Folder-Level Scoping

To limit scanning to specific folders instead of the entire organization:

```bash
FOLDER_ID="123456789012"

gcloud logging sinks create cloudrun-folder-scanner \
  pubsub.googleapis.com/projects/${SECURITY_PROJECT}/topics/${PUBSUB_TOPIC} \
  --folder=${FOLDER_ID} \
  --include-children \
  --log-filter='resource.type="cloud_run_revision"
protoPayload.methodName=~"google.cloud.run.v2.Services.(Create|Update)Service"'
```

## Configuration Reference

### Terraform Variables

| Variable | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `project_id` | string | Yes | - | GCP project ID (6-30 chars, lowercase, digits, hyphens) |
| `region` | string | No | `us-central1` | GCP region for resources |
| `firestore_location` | string | No | `nam5` | Firestore multi-region: `nam5`, `eur3`, `asia1` |
| `qualys_pod` | string | Yes | - | Qualys POD: `US01-US04`, `EU1-EU2`, `IN1`, `AP1-AP2`, `CA1`, `AE1`, `UK1` |
| `qscanner_image` | string | No | `qualys/qscanner:1.25` | Scanner Docker image (pin version for production) |
| `scan_cache_hours` | number | No | `24` | Hours to cache results (1-168) |
| `scan_results_retention_days` | number | No | `90` | Days to retain results (30-365) |
| `notify_severity_threshold` | string | No | `HIGH` | Alert threshold: `CRITICAL` or `HIGH` |
| `max_function_instances` | number | No | `10` | Maximum Cloud Function instances (1-100) |
| `enable_vpc_connector` | bool | No | `false` | Enable VPC connector for private networking |
| `vpc_connector_name` | string | No | `""` | VPC connector resource name |

### Environment Variables

The Cloud Function receives these environment variables:

| Variable | Description |
|----------|-------------|
| `GCP_PROJECT_ID` | Project where infrastructure is deployed |
| `GCP_REGION` | Region for Cloud Run Jobs |
| `SCAN_RESULTS_BUCKET` | Cloud Storage bucket name |
| `QUALYS_POD` | Qualys POD identifier |
| `QUALYS_ACCESS_TOKEN` | API token (injected from Secret Manager) |
| `QSCANNER_IMAGE` | Scanner Docker image |
| `SCAN_TIMEOUT` | Maximum scan duration (seconds) |
| `SCAN_CACHE_HOURS` | Deduplication cache period |
| `NOTIFY_SEVERITY_THRESHOLD` | Alert severity threshold |
| `CLOUDRUN_SERVICE_ACCOUNT` | Service account for scanner jobs |
| `QUALYS_SECRET_REF` | Secret Manager reference for Cloud Run Jobs |

### Terraform Outputs

| Output | Description |
|--------|-------------|
| `function_name` | Cloud Function name |
| `function_url` | Cloud Function URL |
| `scan_results_bucket` | Cloud Storage bucket for results |
| `pubsub_topic` | Pub/Sub topic for events |
| `scanner_service_account` | Cloud Function service account |
| `job_service_account` | Cloud Run Jobs service account |
| `qualys_secret_id` | Secret Manager secret ID |
| `firestore_database` | Firestore database name |

## Operations

### Viewing Scan Results

#### Cloud Storage (Detailed JSON)

```bash
# List all scan results
gsutil ls -r gs://${PROJECT_ID}-qualys-scan-results/

# Download specific result
gsutil cp gs://${PROJECT_ID}-qualys-scan-results/gcr_io_project_app_v1/20240115120000.json .

# View result contents
cat 20240115120000.json | jq '.vulnerabilities'
```

#### Firestore (Queryable Metadata)

```python
from google.cloud import firestore

db = firestore.Client(project='your-project')

# Get recent scans with critical vulnerabilities
scans = db.collection('scan_metadata') \
    .where('vuln_critical', '>', 0) \
    .order_by('timestamp_str', direction=firestore.Query.DESCENDING) \
    .limit(50) \
    .stream()

for scan in scans:
    data = scan.to_dict()
    print(f"{data['image']}: {data['vuln_critical']} critical, {data['vuln_high']} high")
```

### Monitoring

#### Cloud Function Logs

```bash
gcloud functions logs read qualys-cloudrun-scanner \
  --region=us-central1 \
  --limit=100
```

#### Cloud Run Job Status

```bash
# List recent scanner jobs
gcloud run jobs list --region=us-central1 --filter="labels.purpose=qscanner"

# View job executions
gcloud run jobs executions list --job=JOB_NAME --region=us-central1
```

#### Cloud Logging Queries

```bash
# All scanner-related logs
gcloud logging read 'resource.type="cloud_function" OR resource.type="cloud_run_job"
labels.purpose="qscanner"' --limit=100

# Scan errors only
gcloud logging read 'resource.type="cloud_function"
severity>=ERROR' --limit=50
```

### Alerting Integration

The solution logs security alerts for high-severity findings. To integrate with external systems:

1. **Cloud Monitoring**: Create alerting policies based on log-based metrics
2. **Pub/Sub**: Configure `NOTIFICATION_TOPIC` environment variable to publish alerts
3. **Cloud Functions**: Deploy a notification function triggered by the alert topic

## Troubleshooting

### Function Not Triggering

```bash
# Verify log sink is active
gcloud logging sinks describe cloudrun-deployment-sink

# Check Pub/Sub subscription
gcloud pubsub subscriptions list

# Test with manual message
gcloud pubsub topics publish cloudrun-deployment-events --message='{"test": "data"}'
```

### Scan Failures

```bash
# View Cloud Run Job logs
gcloud logging read 'resource.type="cloud_run_job"
labels."run.googleapis.com/job_name"="qscanner-*"' --limit=50

# Check job execution status
gcloud run jobs executions describe EXECUTION_NAME --region=us-central1
```

### Permission Errors

```bash
# Verify service account permissions
gcloud projects get-iam-policy ${PROJECT_ID} \
  --flatten="bindings[].members" \
  --filter="bindings.members:qualys-scanner-function@"

# Check Secret Manager access
gcloud secrets get-iam-policy qualys-access-token
```

### Invalid Qualys Credentials

```bash
# Verify secret exists and has versions
gcloud secrets versions list qualys-access-token

# Test secret access
gcloud secrets versions access latest --secret=qualys-access-token

# Update credentials
echo -n "NEW_TOKEN" | gcloud secrets versions add qualys-access-token --data-file=-
```

### Image Validation Errors

If scans fail with validation errors, check that the container image name:

- Does not contain shell special characters
- Is under 512 characters total length
- Uses valid registry, repository, and tag formats
- Does not include credentials or tokens in the image reference

## Cost Estimation

Approximate monthly costs based on deployment frequency:

| Deployments/Month | Cloud Functions | Cloud Run Jobs | Storage | Firestore | Total |
|-------------------|-----------------|----------------|---------|-----------|-------|
| 100 | $0.50 | $5.00 | $2.50 | $0.50 | $8.50 |
| 500 | $2.50 | $25.00 | $5.00 | $2.00 | $34.50 |
| 1,000 | $5.00 | $50.00 | $10.00 | $4.00 | $69.00 |

Assumptions:
- Cloud Function: 512MB memory, 60s average execution
- Cloud Run Job: 2GB memory, 1 CPU, 5-minute average scan
- Storage: 1MB per scan result, 90-day retention
- Firestore: 1 document write per scan, 10 reads per scan

Costs vary based on image size, vulnerability count, and retention policies.

## Development

### Local Testing

```bash
cd cloud_function

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export GCP_PROJECT_ID=your-project
export GCP_REGION=us-central1
export QUALYS_POD=US02
export QUALYS_ACCESS_TOKEN=your-token
export SCAN_RESULTS_BUCKET=your-bucket
export CLOUDRUN_SERVICE_ACCOUNT=your-sa@project.iam.gserviceaccount.com

# Run with functions-framework
functions-framework --target=process_cloudrun_event --signature-type=cloudevent --debug
```

### Testing with Sample Events

```bash
# Send test CloudEvent
curl -X POST http://localhost:8080 \
  -H "Content-Type: application/cloudevents+json" \
  -d @test_events/cloudrun-service-create.json
```

## License

MIT License - see LICENSE file for details.

## References

- [Qualys Container Security Documentation](https://www.qualys.com/docs/qualys-container-scanning-connector-guide.pdf)
- [Google Cloud Run Jobs](https://cloud.google.com/run/docs/create-jobs)
- [Cloud Functions (2nd gen)](https://cloud.google.com/functions/docs/concepts/version-comparison)
- [Cloud Audit Logs](https://cloud.google.com/logging/docs/audit)
- [Secret Manager](https://cloud.google.com/secret-manager/docs)

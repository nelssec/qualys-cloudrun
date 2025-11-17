# Qualys Container Scanner for Google Cloud Run

Automated container image scanning for Cloud Run deployments using Qualys qscanner. Scans happen automatically when you deploy or update Cloud Run services.

## Overview

When you deploy a Cloud Run service, this system automatically scans the container image for vulnerabilities and compliance issues. The workflow is:

1. Cloud Audit Logs capture the Cloud Run deployment event
2. Cloud Function processes the event and extracts container images
3. Temporary Cloud Run Job spins up running the Qualys qscanner container
4. Scanner analyzes the image and produces vulnerability/compliance data
5. Results stored in Cloud Storage (detailed JSON) and Firestore (queryable metadata)
6. Optional alerting on high-severity findings
7. Scanner job automatically deleted after completion

## Architecture

```
Cloud Run Deployment
        ↓
  Cloud Audit Logs
        ↓
   Pub/Sub Topic
        ↓
  Cloud Function (Event Processor)
        ↓
  Cloud Run Job (qscanner)
        ↓
  Cloud Storage (Results) + Firestore (Metadata)
```

### Components

- Cloud Function: Processes deployment events and orchestrates scans
- Cloud Run Jobs: Ephemeral containers running Qualys qscanner
- Cloud Storage: Stores detailed scan results as JSON files
- Firestore: Indexes scan metadata for querying
- Secret Manager: Stores Qualys credentials
- Pub/Sub: Event routing from Cloud Audit Logs
- Cloud Logging: Monitoring and troubleshooting

## Features

- Event-driven scanning triggered by Cloud Run deployments
- Uses official qualys/qscanner Docker image
- No permanent scanning infrastructure - jobs are ephemeral
- Scan caching to avoid duplicates (default 24 hours)
- Single project or organization-wide deployment
- Full vulnerability details with severity levels and compliance checks
- Optional alerting for high-severity findings
- Infrastructure deployed via Terraform

## Prerequisites

- GCP project with billing enabled
- Terraform >= 1.0
- Qualys subscription with API access
- `gcloud` CLI configured

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/nelssec/qualys-cloudrun.git
cd qualys-cloudrun
```

### 2. Configure Variables

```bash
cd infrastructure
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
```

### 3. Deploy Infrastructure

```bash
terraform init
terraform plan
terraform apply
```

### 4. Configure Qualys Credentials

```bash
# Set your Qualys access token
echo -n "YOUR_QUALYS_TOKEN" | gcloud secrets versions add qualys-access-token --data-file=-
```

### 5. Deploy a Cloud Run Service

Deploy any Cloud Run service and watch the automatic scanning:

```bash
gcloud run deploy myapp \
  --image=gcr.io/my-project/myapp:latest \
  --region=us-central1
```

## Configuration

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `project_id` | GCP Project ID | `my-project-123` |
| `qualys_pod` | Qualys POD URL | `qualysapi.qualys.com` |

### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `region` | GCP region | `us-central1` |
| `firestore_location` | Firestore multi-region | `nam5` |
| `qscanner_image` | Scanner image | `qualys/qscanner:latest` |
| `scan_cache_hours` | Cache period | `24` |
| `notify_severity_threshold` | Alert threshold | `HIGH` |

### Environment Variables

Terraform configures these environment variables for the Cloud Function:

- GCP_PROJECT_ID: Project where infrastructure is deployed
- GCP_REGION: Region for Cloud Run Jobs
- SCAN_RESULTS_BUCKET: Cloud Storage bucket name
- QUALYS_POD: Qualys POD URL
- QUALYS_ACCESS_TOKEN: API token from Secret Manager
- QSCANNER_IMAGE: Scanner image (default: qualys/qscanner:latest)
- SCAN_TIMEOUT: Maximum scan duration in seconds (default: 1800)
- SCAN_CACHE_HOURS: How long to cache scan results (default: 24)
- NOTIFY_SEVERITY_THRESHOLD: Alert threshold (CRITICAL or HIGH)
- CLOUDRUN_SERVICE_ACCOUNT: Service account for scanner jobs

The qscanner command executed is:

```bash
qscanner image <image:tag> --pod <qualys_pod> --skip-verify-tls --output-format json
```

Authentication uses the QUALYS_ACCESS_TOKEN environment variable.

## Viewing Scan Results

### Query Firestore Metadata

```bash
# Using gcloud
gcloud firestore export gs://your-bucket/export --collection-ids=scan_metadata
```

### Download Detailed Results from Cloud Storage

```bash
# List all scan results
gsutil ls gs://your-project-qualys-scan-results/

# Download a specific result
gsutil cp gs://your-project-qualys-scan-results/gcr_io_project_app_latest/20240101120000.json .
```

### View in Cloud Console

1. Navigate to **Cloud Storage** → Your scan results bucket
2. Browse by image name and scan ID
3. Download JSON files for detailed analysis

## Monitoring

### Cloud Function Logs

```bash
gcloud functions logs read qualys-cloudrun-scanner \
  --region=us-central1 \
  --limit=50
```

### Active Cloud Run Jobs

```bash
gcloud run jobs list --region=us-central1 | grep qscanner
```

### Scan Statistics

Query Firestore for scan statistics:

```python
from google.cloud import firestore

db = firestore.Client()
scans = db.collection('scan_metadata') \
  .where('vuln_critical', '>', 0) \
  .stream()

for scan in scans:
    print(f"{scan.to_dict()['image']}: {scan.to_dict()['vuln_critical']} critical")
```

## Troubleshooting

### Function Not Triggering

**Check Pub/Sub subscription:**
```bash
gcloud pubsub subscriptions list
gcloud pubsub subscriptions pull cloudrun-deployment-events --limit=5
```

**Verify log sink:**
```bash
gcloud logging sinks describe cloudrun-deployment-sink
```

### Scan Failures

**Check Cloud Run Jobs:**
```bash
gcloud run jobs describe qscanner-<name> --region=us-central1
gcloud run jobs executions list --job=qscanner-<name> --region=us-central1
```

**View job logs:**
```bash
gcloud logging read "resource.type=cloud_run_job" --limit=100
```

### Invalid Qualys Credentials

**Verify secret:**
```bash
gcloud secrets versions access latest --secret=qualys-access-token
```

**Update secret:**
```bash
echo -n "NEW_TOKEN" | gcloud secrets versions add qualys-access-token --data-file=-
```

## Security Considerations

- **Service Accounts**: Minimal permissions following least-privilege principle
- **Secret Management**: Credentials stored in Secret Manager
- **Ephemeral Jobs**: Scanner containers are temporary and auto-deleted
- **IAM**: Function uses managed identity for GCP API access
- **Network**: Jobs run in default VPC (can be customized for VPC SC)

## Cost Estimation

Approximate monthly costs for 100 daily deployments:

| Service | Usage | Cost |
|---------|-------|------|
| Cloud Functions | 3000 invocations, 512MB | ~$0.50 |
| Cloud Run Jobs | 3000 executions, 2GB, 5min avg | ~$5.00 |
| Cloud Storage | 100GB storage, operations | ~$2.50 |
| Firestore | 3000 writes, 10000 reads | ~$0.50 |
| **Total** | | **~$8.50/month** |

Costs scale with deployment frequency and scan duration.

## Development

### Local Testing

```bash
cd cloud_function

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export GCP_PROJECT_ID=your-project
export QUALYS_POD=qualysapi.qualys.com
export QUALYS_ACCESS_TOKEN=your-token
export SCAN_RESULTS_BUCKET=your-bucket

# Test with functions-framework
functions-framework --target=process_cloudrun_event --debug
```

### Run Unit Tests

```bash
python -m pytest tests/
```

## Organization-Wide Scanning

You can deploy the scanner once to monitor all Cloud Run deployments across your entire GCP organization. Instead of deploying in each project, deploy in a central security project and configure an organization-level log sink.

See `ORGANIZATION_WIDE.md` for detailed setup instructions.

## Comparison with qualys-aci

This is the GCP equivalent of the [qualys-aci](https://github.com/nelssec/qualys-aci) solution for Azure. Same scanner image, different cloud platform.

| Component | Azure (qualys-aci) | GCP (qualys-cloudrun) |
|-----------|-------------------|---------------------|
| Compute | Azure Container Instances | Cloud Run Jobs |
| Functions | Azure Functions | Cloud Functions |
| Events | Event Grid | Pub/Sub + Audit Logs |
| Storage | Blob + Table Storage | Cloud Storage + Firestore |
| IaC | Bicep | Terraform |
| Scanner | qualys/qscanner:latest | qualys/qscanner:latest |

Both implementations use the same qscanner command with QUALYS_ACCESS_TOKEN authentication.

## Contributing

Contributions welcome! Please open issues or pull requests.

## License

MIT License - see LICENSE file

## Support

For issues:
- GitHub Issues: https://github.com/nelssec/qualys-cloudrun/issues
- Qualys Support: https://www.qualys.com/support/

## Resources

- [Qualys qscanner Documentation](https://www.qualys.com/docs/qualys-container-scanning-api-guide.pdf)
- [Google Cloud Run Jobs](https://cloud.google.com/run/docs/create-jobs)
- [Cloud Functions Documentation](https://cloud.google.com/functions/docs)
- [Cloud Audit Logs](https://cloud.google.com/logging/docs/audit)

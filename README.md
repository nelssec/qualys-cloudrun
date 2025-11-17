# Qualys Container Scanner for Google Cloud Run

Event-driven container image scanning for Google Cloud Run using Qualys qscanner. Automatically scan container images deployed to Cloud Run services for vulnerabilities and compliance issues.

## Overview

This solution provides automated security scanning of container images deployed to Google Cloud Run. When you deploy or update a Cloud Run service, the system:

1. **Detects** the deployment via Cloud Audit Logs
2. **Triggers** a Cloud Function to process the event
3. **Launches** a temporary Cloud Run Job running the official Qualys qscanner
4. **Scans** the container image for vulnerabilities and compliance issues
5. **Stores** results in Cloud Storage and Firestore
6. **Alerts** on high-severity findings (optional)
7. **Cleans up** the scan job automatically

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

- **Cloud Function**: Processes deployment events and orchestrates scans
- **Cloud Run Jobs**: Ephemeral containers running Qualys qscanner
- **Cloud Storage**: Stores detailed scan results as JSON files
- **Firestore**: Indexes scan metadata for querying
- **Secret Manager**: Securely stores Qualys credentials
- **Pub/Sub**: Event routing from Cloud Audit Logs
- **Cloud Logging**: Monitoring and troubleshooting

## Features

- ✅ **Event-Driven**: Automatic scanning on Cloud Run deployments
- ✅ **Official Scanner**: Uses the official `qualys/qscanner` Docker image
- ✅ **Ephemeral Infrastructure**: No permanent scanning infrastructure
- ✅ **Scan Caching**: Avoid duplicate scans with configurable cache period (default: 24 hours)
- ✅ **Multi-Project Support**: Can scan images from different GCP projects
- ✅ **Comprehensive Results**: Vulnerability details, severity levels, compliance checks
- ✅ **Alerting**: Optional notifications for high-severity findings
- ✅ **Fully Automated**: Terraform-based infrastructure deployment

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

### Environment Variables (Cloud Function)

The Cloud Function is configured with these environment variables (set automatically by Terraform):

- `GCP_PROJECT_ID`: GCP project ID
- `GCP_REGION`: Deployment region
- `SCAN_RESULTS_BUCKET`: Cloud Storage bucket for results
- `QUALYS_POD`: Qualys POD URL
- `QUALYS_ACCESS_TOKEN`: Qualys API token (from Secret Manager)
- `QSCANNER_IMAGE`: Scanner Docker image
- `SCAN_TIMEOUT`: Maximum scan time in seconds (default: 1800)
- `SCAN_CACHE_HOURS`: Cache period to avoid duplicate scans
- `NOTIFY_SEVERITY_THRESHOLD`: Minimum severity for alerts (CRITICAL or HIGH)
- `CLOUDRUN_SERVICE_ACCOUNT`: Service account for Cloud Run Jobs

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

## Multi-Project Scanning

To scan Cloud Run services across multiple GCP projects:

1. Deploy the scanner in a central "security" project
2. Configure Cloud Audit Log sinks in each target project
3. Route all logs to the central Pub/Sub topic
4. Grant the scanner service account permissions in target projects

See `MULTI_PROJECT.md` for detailed instructions.

## Comparison with qualys-aci

This solution is the Google Cloud Platform equivalent of [qualys-aci](https://github.com/nelssec/qualys-aci):

| Feature | qualys-aci (Azure) | qualys-cloudrun (GCP) |
|---------|-------------------|---------------------|
| Compute | Azure Container Instances | Cloud Run Jobs |
| Functions | Azure Functions | Cloud Functions |
| Events | Event Grid | Pub/Sub + Audit Logs |
| Storage | Blob + Table Storage | Cloud Storage + Firestore |
| IaC | Bicep | Terraform |
| Scanner | qualys/qscanner | qualys/qscanner |

Both use the same official Qualys scanner image and provide equivalent functionality.

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

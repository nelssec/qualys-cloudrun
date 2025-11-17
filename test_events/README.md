# Test Events

Sample Cloud Audit Log events for testing the Cloud Function locally.

## Usage

To test the function locally with sample events:

```bash
cd cloud_function

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export GCP_PROJECT_ID=your-project
export GCP_REGION=us-central1
export SCAN_RESULTS_BUCKET=your-bucket
export QUALYS_POD=qualysapi.qualys.com
export QUALYS_ACCESS_TOKEN=your-token
export CLOUDRUN_SERVICE_ACCOUNT=scanner@your-project.iam.gserviceaccount.com

# Test with functions-framework
functions-framework --target=process_cloudrun_event --debug
```

In another terminal, send a test event:

```bash
# Encode the test event as base64 (Pub/Sub format)
EVENT_DATA=$(cat ../test_events/cloudrun-service-create.json | base64 -w 0)

# Send test request
curl -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d "{
    \"data\": \"${EVENT_DATA}\",
    \"attributes\": {
      \"event_type\": \"google.cloud.audit.log.v1.written\"
    }
  }"
```

## Event Files

- `cloudrun-service-create.json`: Cloud Run service creation event
- `cloudrun-service-update.json`: Cloud Run service update event

## Event Structure

Cloud Audit Log events are wrapped in Pub/Sub messages. The function receives:

```json
{
  "data": "base64-encoded-audit-log",
  "attributes": {
    "event_type": "google.cloud.audit.log.v1.written"
  }
}
```

The decoded audit log contains:
- `protoPayload.methodName`: The API method called
- `protoPayload.request.template.containers`: Container images
- `resource.labels`: Project, service, and location information

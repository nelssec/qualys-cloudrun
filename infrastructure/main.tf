/**
 * Qualys Container Scanner for Google Cloud Run
 *
 * This Terraform configuration deploys:
 * - Cloud Function for event processing
 * - Cloud Storage bucket for scan results
 * - Firestore database for metadata
 * - Pub/Sub topic and subscription for Cloud Audit Logs
 * - Service accounts and IAM permissions
 * - Secret Manager for credentials
 */

terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Enable required APIs
resource "google_project_service" "required_apis" {
  for_each = toset([
    "run.googleapis.com",
    "cloudfunctions.googleapis.com",
    "cloudbuild.googleapis.com",
    "storage.googleapis.com",
    "firestore.googleapis.com",
    "pubsub.googleapis.com",
    "logging.googleapis.com",
    "secretmanager.googleapis.com",
    "eventarc.googleapis.com"
  ])

  service            = each.key
  disable_on_destroy = false
}

# Cloud Storage bucket for scan results
resource "google_storage_bucket" "scan_results" {
  name          = "${var.project_id}-qualys-scan-results"
  location      = var.region
  force_destroy = false

  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 90 # Keep results for 90 days
    }
    action {
      type = "Delete"
    }
  }

  depends_on = [google_project_service.required_apis]
}

# Firestore database (uses default database)
resource "google_firestore_database" "scan_metadata" {
  project     = var.project_id
  name        = "(default)"
  location_id = var.firestore_location
  type        = "FIRESTORE_NATIVE"

  depends_on = [google_project_service.required_apis]
}

# Service account for Cloud Function
resource "google_service_account" "scanner_function" {
  account_id   = "qualys-scanner-function"
  display_name = "Qualys Scanner Cloud Function"
  description  = "Service account for Qualys container scanner Cloud Function"
}

# Service account for Cloud Run Jobs
resource "google_service_account" "scanner_jobs" {
  account_id   = "qualys-scanner-jobs"
  display_name = "Qualys Scanner Cloud Run Jobs"
  description  = "Service account for Qualys scanner Cloud Run Jobs"
}

# IAM permissions for function service account
resource "google_project_iam_member" "function_permissions" {
  for_each = toset([
    "roles/storage.objectAdmin",
    "roles/datastore.user",
    "roles/logging.logWriter",
    "roles/run.admin",
    "roles/secretmanager.secretAccessor"
  ])

  project = var.project_id
  role    = each.key
  member  = "serviceAccount:${google_service_account.scanner_function.email}"
}

# IAM permissions for job service account (minimal permissions)
resource "google_project_iam_member" "job_permissions" {
  for_each = toset([
    "roles/logging.logWriter"
  ])

  project = var.project_id
  role    = each.key
  member  = "serviceAccount:${google_service_account.scanner_jobs.email}"
}

# Secret for Qualys access token
resource "google_secret_manager_secret" "qualys_token" {
  secret_id = "qualys-access-token"

  replication {
    auto {}
  }

  depends_on = [google_project_service.required_apis]
}

# Grant function access to secret
resource "google_secret_manager_secret_iam_member" "function_secret_access" {
  secret_id = google_secret_manager_secret.qualys_token.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.scanner_function.email}"
}

# Pub/Sub topic for Cloud Audit Logs
resource "google_pubsub_topic" "cloudrun_events" {
  name = "cloudrun-deployment-events"

  depends_on = [google_project_service.required_apis]
}

# Log sink to capture Cloud Run events
resource "google_logging_project_sink" "cloudrun_sink" {
  name        = "cloudrun-deployment-sink"
  destination = "pubsub.googleapis.com/${google_pubsub_topic.cloudrun_events.id}"

  # Filter for Cloud Run service create/update events
  filter = <<-EOT
    resource.type="cloud_run_revision"
    protoPayload.methodName=~"google.cloud.run.v2.Services.(Create|Update)Service"
  EOT

  unique_writer_identity = true
}

# Grant log sink permission to publish to Pub/Sub
resource "google_pubsub_topic_iam_member" "log_sink_publisher" {
  topic  = google_pubsub_topic.cloudrun_events.name
  role   = "roles/pubsub.publisher"
  member = google_logging_project_sink.cloudrun_sink.writer_identity
}

# Archive Cloud Function code
data "archive_file" "function_source" {
  type        = "zip"
  source_dir  = "${path.module}/../cloud_function"
  output_path = "${path.module}/function-source.zip"
}

# Upload function source to Cloud Storage
resource "google_storage_bucket" "function_source" {
  name          = "${var.project_id}-function-source"
  location      = var.region
  force_destroy = true

  uniform_bucket_level_access = true
}

resource "google_storage_bucket_object" "function_source" {
  name   = "function-source-${data.archive_file.function_source.output_md5}.zip"
  bucket = google_storage_bucket.function_source.name
  source = data.archive_file.function_source.output_path
}

# Cloud Function (2nd gen)
resource "google_cloudfunctions2_function" "scanner_function" {
  name        = "qualys-cloudrun-scanner"
  location    = var.region
  description = "Processes Cloud Run deployment events and triggers Qualys scans"

  build_config {
    runtime     = "python311"
    entry_point = "process_cloudrun_event"

    source {
      storage_source {
        bucket = google_storage_bucket.function_source.name
        object = google_storage_bucket_object.function_source.name
      }
    }
  }

  service_config {
    max_instance_count    = 10
    available_memory      = "512Mi"
    timeout_seconds       = 540
    service_account_email = google_service_account.scanner_function.email

    environment_variables = {
      GCP_PROJECT_ID            = var.project_id
      GCP_REGION                = var.region
      SCAN_RESULTS_BUCKET       = google_storage_bucket.scan_results.name
      QUALYS_POD                = var.qualys_pod
      QSCANNER_IMAGE            = var.qscanner_image
      SCAN_TIMEOUT              = "1800"
      SCAN_CACHE_HOURS          = var.scan_cache_hours
      NOTIFY_SEVERITY_THRESHOLD = var.notify_severity_threshold
      CLOUDRUN_SERVICE_ACCOUNT  = google_service_account.scanner_jobs.email
    }

    secret_environment_variables {
      key        = "QUALYS_ACCESS_TOKEN"
      project_id = var.project_id
      secret     = google_secret_manager_secret.qualys_token.secret_id
      version    = "latest"
    }
  }

  event_trigger {
    trigger_region = var.region
    event_type     = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic   = google_pubsub_topic.cloudrun_events.id
    retry_policy   = "RETRY_POLICY_RETRY"
  }

  depends_on = [
    google_project_service.required_apis,
    google_project_iam_member.function_permissions
  ]
}

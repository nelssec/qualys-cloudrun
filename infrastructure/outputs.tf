/**
 * Outputs for Qualys Cloud Run Scanner
 */

output "function_name" {
  description = "Name of the Cloud Function"
  value       = google_cloudfunctions2_function.scanner_function.name
}

output "function_url" {
  description = "URL of the Cloud Function"
  value       = google_cloudfunctions2_function.scanner_function.service_config[0].uri
}

output "scan_results_bucket" {
  description = "Cloud Storage bucket for scan results"
  value       = google_storage_bucket.scan_results.name
}

output "pubsub_topic" {
  description = "Pub/Sub topic for Cloud Run events"
  value       = google_pubsub_topic.cloudrun_events.name
}

output "scanner_service_account" {
  description = "Service account email for scanner function"
  value       = google_service_account.scanner_function.email
}

output "job_service_account" {
  description = "Service account email for Cloud Run Jobs"
  value       = google_service_account.scanner_jobs.email
}

output "qualys_secret_id" {
  description = "Secret Manager secret ID for Qualys token"
  value       = google_secret_manager_secret.qualys_token.secret_id
}

output "firestore_database" {
  description = "Firestore database name"
  value       = google_firestore_database.scan_metadata.name
}

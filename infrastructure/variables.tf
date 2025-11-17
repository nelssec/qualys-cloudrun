/**
 * Variables for Qualys Cloud Run Scanner
 */

variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP region for resources"
  type        = string
  default     = "us-central1"
}

variable "firestore_location" {
  description = "Firestore location (must be a multi-region location)"
  type        = string
  default     = "nam5" # North America
}

variable "qualys_pod" {
  description = "Qualys POD URL (e.g., qualysapi.qualys.com)"
  type        = string
}

variable "qscanner_image" {
  description = "Qualys qscanner Docker image"
  type        = string
  default     = "qualys/qscanner:latest"
}

variable "scan_cache_hours" {
  description = "Hours to cache scan results (avoid duplicate scans)"
  type        = number
  default     = 24
}

variable "notify_severity_threshold" {
  description = "Minimum severity level for alerts (CRITICAL or HIGH)"
  type        = string
  default     = "HIGH"

  validation {
    condition     = contains(["CRITICAL", "HIGH"], var.notify_severity_threshold)
    error_message = "Notify threshold must be CRITICAL or HIGH"
  }
}

/**
 * Variables for Qualys Cloud Run Scanner
 * Security-hardened configuration for enterprise deployments
 */

variable "project_id" {
  description = "GCP Project ID"
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "Project ID must be 6-30 characters, lowercase letters, digits, and hyphens."
  }
}

variable "region" {
  description = "GCP region for resources"
  type        = string
  default     = "us-central1"

  validation {
    condition = contains([
      "us-central1", "us-east1", "us-east4", "us-west1", "us-west2", "us-west3", "us-west4",
      "europe-west1", "europe-west2", "europe-west3", "europe-west4", "europe-west6",
      "asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3",
      "asia-south1", "asia-southeast1", "australia-southeast1", "southamerica-east1"
    ], var.region)
    error_message = "Region must be a valid GCP region."
  }
}

variable "firestore_location" {
  description = "Firestore location (must be a multi-region location)"
  type        = string
  default     = "nam5" # North America

  validation {
    condition     = contains(["nam5", "eur3", "asia1"], var.firestore_location)
    error_message = "Firestore location must be a valid multi-region: nam5, eur3, or asia1."
  }
}

variable "qualys_pod" {
  description = "Qualys POD identifier (e.g., US01, US02, US03, EU1, EU2, IN1)"
  type        = string

  validation {
    condition     = can(regex("^(US0[1-4]|EU[1-2]|IN1|AP[1-2]|CA1|AE1|UK1)$", var.qualys_pod))
    error_message = "Qualys POD must be a valid identifier: US01-US04, EU1-EU2, IN1, AP1-AP2, CA1, AE1, UK1."
  }
}

variable "qscanner_image" {
  description = "Qualys qscanner Docker image. For production, pin to a specific version."
  type        = string
  default     = "qualys/qscanner:1.25" # Pinned version for stability

  validation {
    condition     = can(regex("^qualys/qscanner:[a-zA-Z0-9][a-zA-Z0-9._-]*$", var.qscanner_image))
    error_message = "qscanner image must be from qualys/qscanner with a valid tag."
  }
}

variable "scan_cache_hours" {
  description = "Hours to cache scan results (avoid duplicate scans)"
  type        = number
  default     = 24

  validation {
    condition     = var.scan_cache_hours >= 1 && var.scan_cache_hours <= 168
    error_message = "Scan cache hours must be between 1 and 168 (1 week)."
  }
}

variable "scan_results_retention_days" {
  description = "Number of days to retain scan results in Cloud Storage"
  type        = number
  default     = 90

  validation {
    condition     = var.scan_results_retention_days >= 30 && var.scan_results_retention_days <= 365
    error_message = "Retention days must be between 30 and 365 for compliance."
  }
}

variable "notify_severity_threshold" {
  description = "Minimum severity level for alerts (CRITICAL or HIGH)"
  type        = string
  default     = "HIGH"

  validation {
    condition     = contains(["CRITICAL", "HIGH"], var.notify_severity_threshold)
    error_message = "Notify threshold must be CRITICAL or HIGH."
  }
}

variable "max_function_instances" {
  description = "Maximum number of Cloud Function instances"
  type        = number
  default     = 10

  validation {
    condition     = var.max_function_instances >= 1 && var.max_function_instances <= 100
    error_message = "Max instances must be between 1 and 100."
  }
}

variable "enable_vpc_connector" {
  description = "Enable VPC connector for private networking (requires vpc_connector_name)"
  type        = bool
  default     = false
}

variable "vpc_connector_name" {
  description = "VPC connector name for private networking (format: projects/PROJECT/locations/REGION/connectors/NAME)"
  type        = string
  default     = ""
}

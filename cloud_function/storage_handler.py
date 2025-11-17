"""
Google Cloud Storage handler for scan results and metadata
"""
import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional
from google.cloud import storage
from google.cloud import firestore


class StorageHandler:
    """
    Handles storage of scan results and tracking in Google Cloud Storage
    Uses Cloud Storage for detailed results and Firestore for metadata
    """

    def __init__(self, project_id: str, bucket_name: str):
        """
        Initialize storage handler

        Args:
            project_id: GCP project ID
            bucket_name: Cloud Storage bucket name for results
        """
        self.project_id = project_id
        self.bucket_name = bucket_name

        self.storage_client = storage.Client(project=project_id)
        self.firestore_client = firestore.Client(project=project_id)

        # Collection names
        self.metadata_collection = 'scan_metadata'

        # Initialize storage
        self._ensure_storage_exists()

    def _ensure_storage_exists(self):
        """Create bucket if it doesn't exist"""
        try:
            # Check if bucket exists, create if not
            bucket = self.storage_client.bucket(self.bucket_name)
            if not bucket.exists():
                bucket = self.storage_client.create_bucket(self.bucket_name)
                logging.info(f'Created Cloud Storage bucket: {self.bucket_name}')
            else:
                logging.debug(f'Bucket {self.bucket_name} already exists')

        except Exception as e:
            logging.warning(f'Error ensuring bucket exists: {str(e)}')

    def save_scan_result(self, result: Dict):
        """
        Save scan result to storage

        Args:
            result: Scan result dictionary
        """
        try:
            image = result.get('image', 'unknown')
            scan_id = result.get('scan_id', datetime.utcnow().strftime('%Y%m%d%H%M%S'))
            timestamp = result.get('timestamp', datetime.utcnow().isoformat())

            # Save detailed results to Cloud Storage
            blob_name = f'{self._sanitize_name(image)}/{scan_id}.json'
            bucket = self.storage_client.bucket(self.bucket_name)
            blob = bucket.blob(blob_name)

            blob.metadata = {
                'image': image,
                'scan_id': scan_id,
                'timestamp': timestamp
            }

            blob.upload_from_string(
                json.dumps(result, indent=2),
                content_type='application/json'
            )

            logging.info(f'Saved scan result to Cloud Storage: {blob_name}')

            # Save metadata to Firestore
            doc_ref = self.firestore_client.collection(self.metadata_collection).document(scan_id)

            metadata = {
                'image': image,
                'scan_id': scan_id,
                'timestamp': firestore.SERVER_TIMESTAMP,
                'timestamp_str': timestamp,
                'status': result.get('status', 'UNKNOWN'),
                'container_type': result.get('container_type', 'UNKNOWN'),
                'vuln_critical': result.get('vulnerabilities', {}).get('CRITICAL', 0),
                'vuln_high': result.get('vulnerabilities', {}).get('HIGH', 0),
                'vuln_medium': result.get('vulnerabilities', {}).get('MEDIUM', 0),
                'vuln_low': result.get('vulnerabilities', {}).get('LOW', 0),
                'vuln_total': result.get('vulnerabilities', {}).get('total', 0),
                'compliance_passed': result.get('compliance', {}).get('passed', 0),
                'compliance_failed': result.get('compliance', {}).get('failed', 0),
                'blob_path': blob_name,
                'sanitized_image_name': self._sanitize_name(image)
            }

            doc_ref.set(metadata)
            logging.info(f'Saved scan metadata to Firestore: {scan_id}')

        except Exception as e:
            logging.error(f'Error saving scan result: {str(e)}')
            raise

    def save_error(self, error_info: Dict):
        """
        Save error information

        Args:
            error_info: Error details dictionary
        """
        try:
            timestamp = error_info.get('timestamp', datetime.utcnow().isoformat())
            image = error_info.get('image', 'unknown')

            # Save to Cloud Storage
            blob_name = f'errors/{self._sanitize_name(image)}/{timestamp}.json'
            bucket = self.storage_client.bucket(self.bucket_name)
            blob = bucket.blob(blob_name)

            blob.upload_from_string(
                json.dumps(error_info, indent=2),
                content_type='application/json'
            )

            logging.info(f'Saved error info to Cloud Storage: {blob_name}')

        except Exception as e:
            logging.error(f'Error saving error info: {str(e)}')

    def is_recently_scanned(self, image: str, hours: Optional[int] = None) -> bool:
        """
        Check if an image was scanned recently

        Args:
            image: Image name
            hours: Number of hours to consider as "recent" (defaults to SCAN_CACHE_HOURS env var or 24)

        Returns:
            True if image was scanned within the specified time period
        """
        try:
            if hours is None:
                hours = int(os.environ.get('SCAN_CACHE_HOURS', '24'))

            # Query recent scans from Firestore
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            sanitized_name = self._sanitize_name(image)

            # Query for recent scans of this image
            docs = self.firestore_client.collection(self.metadata_collection) \
                .where('sanitized_image_name', '==', sanitized_name) \
                .where('timestamp_str', '>=', cutoff_time.isoformat()) \
                .limit(1) \
                .stream()

            results = list(docs)

            if results:
                logging.info(f'Found recent scan for {image}')
                return True

            return False

        except Exception as e:
            logging.warning(f'Error checking recent scans: {str(e)}')
            return False

    def _sanitize_name(self, name: str) -> str:
        """
        Sanitize name for use in Cloud Storage paths and Firestore

        Args:
            name: Original name

        Returns:
            Sanitized name
        """
        # Replace special characters with underscores
        sanitized = name.replace('/', '_').replace(':', '_').replace('@', '_')
        # Remove any remaining invalid characters
        sanitized = ''.join(c if c.isalnum() or c in '-_.' else '_' for c in sanitized)
        return sanitized

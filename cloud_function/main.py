"""
Google Cloud Function for processing Cloud Run deployment events
Triggered by Pub/Sub messages from Cloud Audit Logs

This is a Gen2 Cloud Function using CloudEvents format.
"""
import os
import json
import logging
import base64
from datetime import datetime
import functions_framework
from cloudevents.http import CloudEvent
from qualys_scanner_cloudrun import QScannerCloudRun
from image_parser import ImageParser, ImageParserError
from storage_handler import StorageHandler

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _sanitize_tag_value(value: str) -> str:
    """
    Sanitize a value for use in qscanner custom tags

    Args:
        value: Raw value to sanitize

    Returns:
        Sanitized value safe for command line use
    """
    if not value:
        return ''

    # Convert to string and limit length
    value = str(value)[:128]

    # Remove or replace dangerous characters
    # Only allow alphanumeric, hyphen, underscore, period
    sanitized = ''.join(c if c.isalnum() or c in '-_.' else '_' for c in value)

    return sanitized


@functions_framework.cloud_event
def process_cloudrun_event(cloud_event: CloudEvent):
    """
    Cloud Function triggered by Pub/Sub message from Cloud Audit Logs

    Args:
        cloud_event: CloudEvent containing Pub/Sub message data
    """
    event_id = cloud_event.get("id", "unknown")
    logger.info(f'Processing Cloud Run event: {event_id}')

    try:
        # Extract Pub/Sub message data from CloudEvent
        # The data is in cloud_event.data which contains the Pub/Sub message
        pubsub_message = cloud_event.data.get("message", {})
        message_data_b64 = pubsub_message.get("data", "")

        if not message_data_b64:
            logger.warning('No data in Pub/Sub message')
            return

        # Decode base64 message data
        message_data = base64.b64decode(message_data_b64).decode('utf-8')
        audit_log = json.loads(message_data)

        # Extract event details from Cloud Audit Log
        logger.info(f'Audit log method: {audit_log.get("protoPayload", {}).get("methodName")}')

        # Check if this is a Cloud Run service update/create
        method_name = audit_log.get('protoPayload', {}).get('methodName', '')
        if not ('google.cloud.run.v2.Services.CreateService' in method_name or
                'google.cloud.run.v2.Services.UpdateService' in method_name):
            logger.info(f'Ignoring non-Cloud Run service event: {method_name}')
            return

        # Extract service details
        resource = audit_log.get('resource', {})
        project_id = resource.get('labels', {}).get('project_id')
        service_name = resource.get('labels', {}).get('service_name')
        location = resource.get('labels', {}).get('location')

        logger.info(f'Cloud Run service: {service_name} in {location}')

        # Extract container images from the request
        request = audit_log.get('protoPayload', {}).get('request', {})
        images = extract_images_from_service(request)

        if not images:
            logger.warning('No container images found in service definition')
            return

        logger.info(f'Found {len(images)} container images to scan')

        # Initialize scanner and storage
        scanner = QScannerCloudRun(project_id=project_id)

        storage = StorageHandler(
            project_id=os.environ['GCP_PROJECT_ID'],
            bucket_name=os.environ['SCAN_RESULTS_BUCKET']
        )

        # Process each image
        results = []
        for image in images:
            logger.info(f'Processing image: {image}')

            try:
                # Security: Validate and parse image name
                try:
                    image_info = ImageParser.parse(image)
                except ImageParserError as parse_error:
                    logger.warning(f'Invalid image name rejected: {image} - {str(parse_error)}')
                    storage.save_error({
                        'timestamp': datetime.utcnow().isoformat(),
                        'image': image[:256],  # Truncate for safety
                        'error': f'Invalid image name: {str(parse_error)}',
                        'error_type': 'VALIDATION_ERROR',
                        'service_name': service_name,
                        'project_id': project_id
                    })
                    continue

                # Check if recently scanned
                if storage.is_recently_scanned(image_info['full_name']):
                    logger.info(f'Image {image} was recently scanned, skipping')
                    continue

                # Custom tags for tracking - sanitize values
                custom_tags = {
                    'container_type': 'cloudrun',
                    'gcp_project': _sanitize_tag_value(project_id),
                    'service_name': _sanitize_tag_value(service_name),
                    'location': _sanitize_tag_value(location),
                    'event_id': _sanitize_tag_value(event_id)
                }

                # Scan the image
                scan_result = scanner.scan_image(
                    registry=image_info['registry'],
                    repository=image_info['repository'],
                    tag=image_info['tag'],
                    digest=image_info.get('digest'),
                    custom_tags=custom_tags
                )

                # Prepare result record
                result_record = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'container_type': 'cloudrun',
                    'image': image,
                    'project_id': project_id,
                    'service_name': service_name,
                    'location': location,
                    'scan_id': scan_result.get('scan_id'),
                    'status': scan_result.get('status'),
                    'vulnerabilities': scan_result.get('vulnerabilities', {}),
                    'compliance': scan_result.get('compliance', {})
                }

                # Save results
                storage.save_scan_result(result_record)
                results.append(result_record)

                # Check if alert needed
                if should_alert(result_record):
                    send_alert(result_record)

            except Exception as img_error:
                logger.error(f'Error processing image {image}: {str(img_error)}')
                storage.save_error({
                    'timestamp': datetime.utcnow().isoformat(),
                    'image': image[:256],  # Truncate for safety
                    'error': str(img_error),
                    'error_type': 'SCAN_ERROR',
                    'service_name': service_name,
                    'project_id': project_id
                })

        logger.info(f'Successfully processed {len(results)} images')

    except Exception as e:
        logger.error(f'Error processing event: {str(e)}')
        raise


def extract_images_from_service(service_request: dict) -> list:
    """
    Extract container images from Cloud Run service request

    Args:
        service_request: Service request from audit log

    Returns:
        List of container image names
    """
    images = []

    try:
        # Cloud Run v2 API structure
        template = service_request.get('template', {})
        containers = template.get('containers', [])

        for container in containers:
            image = container.get('image')
            if image:
                images.append(image)

    except Exception as e:
        logger.error(f'Error extracting images: {str(e)}')

    return images


def should_alert(scan_result: dict) -> bool:
    """
    Determine if an alert should be sent based on vulnerability severity

    Args:
        scan_result: Scan result dictionary

    Returns:
        True if alert should be sent
    """
    notify_threshold = os.environ.get('NOTIFY_SEVERITY_THRESHOLD', 'HIGH')

    vulnerabilities = scan_result.get('vulnerabilities', {})
    critical_count = vulnerabilities.get('CRITICAL', 0)
    high_count = vulnerabilities.get('HIGH', 0)

    if notify_threshold == 'CRITICAL':
        return critical_count > 0
    elif notify_threshold == 'HIGH':
        return critical_count > 0 or high_count > 0

    return False


def send_alert(scan_result: dict):
    """
    Send alert for high-severity vulnerabilities

    Args:
        scan_result: Scan result dictionary
    """
    try:
        # You can integrate with Cloud Pub/Sub, Cloud Monitoring, or email services
        logger.warning(
            f'SECURITY ALERT: High severity vulnerabilities found in {scan_result["image"]}. '
            f'Service: {scan_result.get("service_name")} '
            f'Vulnerabilities: {scan_result["vulnerabilities"]}'
        )

        # Example: Publish to Pub/Sub topic for alerts
        notification_topic = os.environ.get('NOTIFICATION_TOPIC')
        if notification_topic:
            from google.cloud import pubsub_v1

            publisher = pubsub_v1.PublisherClient()
            message_data = json.dumps({
                'severity': 'HIGH',
                'image': scan_result['image'],
                'service': scan_result.get('service_name'),
                'vulnerabilities': scan_result['vulnerabilities'],
                'timestamp': scan_result['timestamp']
            }).encode('utf-8')

            publisher.publish(notification_topic, message_data)
            logger.info(f'Alert published to {notification_topic}')

    except Exception as e:
        logger.error(f'Error sending alert: {str(e)}')

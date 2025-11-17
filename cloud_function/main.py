"""
Google Cloud Function for processing Cloud Run deployment events
Triggered by Pub/Sub messages from Cloud Audit Logs
"""
import os
import json
import logging
import base64
from datetime import datetime
from qualys_scanner_cloudrun import QScannerCloudRun
from image_parser import ImageParser
from storage_handler import StorageHandler

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def process_cloudrun_event(event, context):
    """
    Cloud Function triggered by Pub/Sub message from Cloud Audit Logs

    Args:
        event: Pub/Sub message event
        context: Cloud Function context
    """
    logger.info(f'Processing Cloud Run event: {context.event_id}')

    try:
        # Decode Pub/Sub message
        if 'data' in event:
            message_data = base64.b64decode(event['data']).decode('utf-8')
            audit_log = json.loads(message_data)
        else:
            logger.warning('No data in Pub/Sub message')
            return

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
                image_info = ImageParser.parse(image)

                # Check if recently scanned
                if storage.is_recently_scanned(image_info['full_name']):
                    logger.info(f'Image {image} was recently scanned, skipping')
                    continue

                # Custom tags for tracking
                custom_tags = {
                    'container_type': 'cloudrun',
                    'gcp_project': project_id,
                    'service_name': service_name,
                    'location': location,
                    'event_id': context.event_id
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
                    'image': image,
                    'error': str(img_error),
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

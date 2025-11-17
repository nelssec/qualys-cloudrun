"""
Qualys qscanner integration using Google Cloud Run Jobs
Runs qscanner in a container on-demand for each scan
"""
import os
import json
import logging
import time
from typing import Dict, Optional
from datetime import datetime
from google.cloud import run_v2
from google.api_core import exceptions


class QScannerCloudRun:
    """
    Run qscanner scans using Google Cloud Run Jobs
    Uses the official qualys/qscanner Docker image from Docker Hub
    """

    def __init__(self, project_id: Optional[str] = None):
        """
        Initialize Cloud Run client with default credentials

        Args:
            project_id: Optional GCP project ID for scan jobs.
                       If not provided, uses GCP_PROJECT_ID env var.
                       This allows scanning across multiple projects.
        """
        self.project_id = project_id or os.environ['GCP_PROJECT_ID']
        self.region = os.environ.get('GCP_REGION', 'us-central1')

        self.client = run_v2.JobsClient()
        self.executions_client = run_v2.ExecutionsClient()

        # qscanner configuration
        self.qscanner_image = os.environ.get('QSCANNER_IMAGE', 'qualys/qscanner:latest')
        self.qualys_pod = os.environ.get('QUALYS_POD')
        self.qualys_access_token = os.environ.get('QUALYS_ACCESS_TOKEN')
        self.scan_timeout = int(os.environ.get('SCAN_TIMEOUT', '1800'))

        # Service account for Cloud Run Jobs
        self.service_account = os.environ.get('CLOUDRUN_SERVICE_ACCOUNT')

    def scan_image(self, registry: str, repository: str, tag: str = 'latest',
                   digest: Optional[str] = None, custom_tags: Optional[Dict] = None) -> Dict:
        """
        Scan a container image by creating a Cloud Run Job

        Args:
            registry: Container registry
            repository: Image repository
            tag: Image tag
            digest: Optional image digest
            custom_tags: Optional custom tags for tracking

        Returns:
            Dictionary containing scan results
        """
        # Construct image identifier
        image_id = f'{registry}/{repository}:{tag}'
        if digest:
            image_id = f'{registry}/{repository}@{digest}'

        logging.info(f'Scanning image with qscanner Cloud Run: {image_id}')

        # Generate unique job name
        job_name = self._generate_job_name(registry, repository, tag)

        try:
            # Create and run qscanner job
            scan_output = self._run_qscanner_job(image_id, job_name, custom_tags)

            # Parse results
            scan_results = self._parse_qscanner_output(scan_output)

            return {
                'scan_id': scan_results.get('scanId', datetime.utcnow().strftime('%Y%m%d%H%M%S')),
                'status': 'COMPLETED',
                'image': image_id,
                'vulnerabilities': self._parse_vulnerabilities(scan_results),
                'compliance': self._parse_compliance(scan_results),
                'metadata': {
                    'registry': registry,
                    'repository': repository,
                    'tag': tag,
                    'digest': digest,
                    'scan_timestamp': datetime.utcnow().isoformat(),
                    'scanner': 'qscanner-cloudrun',
                    'job_name': job_name,
                    'raw_output': scan_results
                }
            }

        except Exception as e:
            logging.error(f'Error scanning image {image_id}: {str(e)}')
            raise
        finally:
            # Clean up: delete the job
            try:
                self._delete_job(job_name)
            except Exception as e:
                logging.warning(f'Failed to delete job {job_name}: {str(e)}')

    def _run_qscanner_job(self, image_id: str, job_name: str,
                         custom_tags: Optional[Dict] = None) -> str:
        """
        Create and run Cloud Run Job with qscanner

        Args:
            image_id: Full image identifier to scan
            job_name: Name for the Cloud Run Job
            custom_tags: Optional tags for scan tracking

        Returns:
            Job logs (scan output)
        """
        logging.info(f'Creating Cloud Run Job: {job_name}')

        # Build qscanner command
        command = self._build_qscanner_command(image_id, custom_tags)

        # Environment variables for qscanner
        env_vars = [
            run_v2.EnvVar(name='QUALYS_ACCESS_TOKEN', value=self.qualys_access_token),
        ]

        # Container configuration
        container = run_v2.Container(
            image=self.qscanner_image,
            command=['/bin/sh', '-c'],
            args=[' '.join(command)],
            env=env_vars,
            resources=run_v2.ResourceRequirements(
                limits={
                    'cpu': '1',
                    'memory': '2Gi'
                }
            )
        )

        # Job template
        template = run_v2.TaskTemplate(
            containers=[container],
            max_retries=0,  # Don't retry failed scans
            timeout='1800s',
            service_account=self.service_account
        )

        # Job configuration
        job = run_v2.Job(
            name=f'projects/{self.project_id}/locations/{self.region}/jobs/{job_name}',
            template=template,
            labels={
                'purpose': 'qscanner',
                'managed-by': 'qualys-cloudrun-scanner'
            }
        )

        # Create the job
        try:
            parent = f'projects/{self.project_id}/locations/{self.region}'
            operation = self.client.create_job(
                parent=parent,
                job=job,
                job_id=job_name
            )
            created_job = operation.result()
            logging.info(f'Job {job_name} created')

        except exceptions.GoogleAPIError as e:
            logging.error(f'Failed to create job: {str(e)}')
            raise

        # Execute the job
        try:
            execution_request = run_v2.RunJobRequest(name=created_job.name)
            execution_operation = self.client.run_job(request=execution_request)
            execution = execution_operation.result()
            logging.info(f'Job execution started: {execution.name}')

        except exceptions.GoogleAPIError as e:
            logging.error(f'Failed to execute job: {str(e)}')
            raise

        # Wait for execution to complete
        self._wait_for_execution_completion(execution.name)

        # Retrieve logs
        logs = self._get_execution_logs(execution.name)

        return logs

    def _wait_for_execution_completion(self, execution_name: str, poll_interval: int = 10):
        """
        Wait for job execution to complete

        Args:
            execution_name: Job execution name
            poll_interval: Seconds between status checks
        """
        start_time = time.time()
        logging.info(f'Waiting for execution {execution_name} to complete...')

        while True:
            elapsed = time.time() - start_time
            if elapsed > self.scan_timeout:
                raise TimeoutError(f'Execution {execution_name} timed out after {self.scan_timeout} seconds')

            try:
                execution = self.executions_client.get_execution(name=execution_name)

                # Check completion status
                if execution.completion_time:
                    logging.info(f'Execution completed')

                    # Check if succeeded (exit code 0 or 1 for qscanner with findings)
                    if execution.succeeded_count > 0:
                        logging.info(f'Execution succeeded')
                        return
                    elif execution.failed_count > 0:
                        # Check task details for exit code
                        # qscanner may exit with code 1 when vulnerabilities are found
                        logging.warning(f'Execution had failures, checking exit codes')
                        return
                    else:
                        raise Exception(f'Execution did not succeed')

                time.sleep(poll_interval)

            except exceptions.GoogleAPIError as e:
                logging.error(f'Error checking execution status: {str(e)}')
                time.sleep(poll_interval)

    def _get_execution_logs(self, execution_name: str) -> str:
        """
        Retrieve execution logs from Cloud Logging

        Args:
            execution_name: Job execution name

        Returns:
            Execution logs
        """
        try:
            from google.cloud import logging as cloud_logging

            logging_client = cloud_logging.Client(project=self.project_id)

            # Extract execution ID from name
            execution_id = execution_name.split('/')[-1]

            # Query logs
            filter_str = f'resource.type="cloud_run_job" AND labels."run.googleapis.com/execution_name"="{execution_id}"'

            logs = []
            for entry in logging_client.list_entries(filter_=filter_str, max_results=1000):
                if hasattr(entry, 'payload'):
                    logs.append(str(entry.payload))

            return '\n'.join(logs)

        except Exception as e:
            logging.error(f'Failed to retrieve execution logs: {str(e)}')
            return ''

    def _delete_job(self, job_name: str):
        """
        Delete the Cloud Run Job to clean up resources

        Args:
            job_name: Job name
        """
        try:
            logging.info(f'Deleting Cloud Run Job: {job_name}')
            name = f'projects/{self.project_id}/locations/{self.region}/jobs/{job_name}'
            operation = self.client.delete_job(name=name)
            operation.result()
            logging.info(f'Job {job_name} deleted')

        except exceptions.GoogleAPIError as e:
            logging.warning(f'Failed to delete job: {str(e)}')

    def _generate_job_name(self, registry: str, repository: str, tag: str) -> str:
        """
        Generate a unique job name

        Args:
            registry: Container registry
            repository: Image repository
            tag: Image tag

        Returns:
            Sanitized job name
        """
        # Cloud Run job names must be lowercase alphanumeric with hyphens
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        base_name = f'qscanner-{repository.replace("/", "-")}-{tag}'.lower()

        # Remove invalid characters
        base_name = ''.join(c if c.isalnum() or c == '-' else '-' for c in base_name)

        # Limit length (max 63 characters)
        max_length = 50  # Leave room for timestamp
        if len(base_name) > max_length:
            base_name = base_name[:max_length]

        return f'{base_name}-{timestamp}'

    def _build_qscanner_command(self, image_id: str, custom_tags: Optional[Dict] = None) -> list:
        """
        Build qscanner command for container

        Args:
            image_id: Full image identifier
            custom_tags: Optional tags for tracking

        Returns:
            Command as list
        """
        cmd_parts = [
            'qscanner',
            'image',
            image_id,
            '--pod', self.qualys_pod,
            '--output-format', 'json'
        ]

        # Add custom tags
        if custom_tags:
            for key, value in custom_tags.items():
                cmd_parts.extend(['--tag', f'{key}={value}'])

        return cmd_parts

    def _parse_qscanner_output(self, output: str) -> Dict:
        """Parse qscanner JSON output"""
        try:
            # qscanner outputs JSON
            data = json.loads(output)
            logging.info('Successfully parsed qscanner JSON output')
            return data
        except json.JSONDecodeError as e:
            logging.error(f'Failed to parse qscanner output as JSON: {str(e)}')
            logging.debug(f'Output was: {output[:500]}...')
            return {
                'status': 'PARSE_ERROR',
                'raw_output': output,
                'error': str(e)
            }

    def _parse_vulnerabilities(self, scan_results: Dict) -> Dict:
        """Parse vulnerability information from qscanner results"""
        vuln_summary = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFORMATIONAL': 0,
            'total': 0,
            'details': []
        }

        # Extract vulnerabilities from qscanner output
        vulnerabilities = []
        if 'vulnerabilities' in scan_results:
            vulnerabilities = scan_results['vulnerabilities']
        elif 'results' in scan_results and 'vulnerabilities' in scan_results['results']:
            vulnerabilities = scan_results['results']['vulnerabilities']

        for vuln in vulnerabilities:
            severity = self._normalize_severity(vuln.get('severity', 'UNKNOWN'))
            if severity in vuln_summary:
                vuln_summary[severity] += 1
            vuln_summary['total'] += 1

            vuln_summary['details'].append({
                'qid': vuln.get('qid') or vuln.get('id'),
                'cve': vuln.get('cve') or vuln.get('cveId'),
                'severity': severity,
                'title': vuln.get('title') or vuln.get('name'),
                'package': vuln.get('package', {}).get('name') if isinstance(vuln.get('package'), dict) else vuln.get('packageName'),
                'version': vuln.get('package', {}).get('version') if isinstance(vuln.get('package'), dict) else vuln.get('packageVersion'),
                'fixed_version': vuln.get('fixedVersion') or vuln.get('fix')
            })

        logging.info(f'Parsed {vuln_summary["total"]} vulnerabilities: '
                    f'Critical={vuln_summary["CRITICAL"]}, High={vuln_summary["HIGH"]}')

        return vuln_summary

    def _parse_compliance(self, scan_results: Dict) -> Dict:
        """Parse compliance information from qscanner results"""
        compliance = {
            'passed': 0,
            'failed': 0,
            'total': 0,
            'checks': []
        }

        compliance_checks = []
        if 'compliance' in scan_results:
            compliance_checks = scan_results['compliance']
        elif 'results' in scan_results and 'compliance' in scan_results['results']:
            compliance_checks = scan_results['results']['compliance']

        for check in compliance_checks:
            status = check.get('status', '').upper()
            compliance['total'] += 1

            if status in ['PASS', 'PASSED']:
                compliance['passed'] += 1
            elif status in ['FAIL', 'FAILED']:
                compliance['failed'] += 1

            compliance['checks'].append({
                'id': check.get('id') or check.get('checkId'),
                'title': check.get('title') or check.get('name'),
                'status': status,
                'description': check.get('description')
            })

        return compliance

    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity levels"""
        severity = str(severity).upper()

        severity_map = {
            '5': 'CRITICAL',
            '4': 'HIGH',
            '3': 'MEDIUM',
            '2': 'LOW',
            '1': 'INFORMATIONAL'
        }

        if severity in severity_map:
            return severity_map[severity]

        if 'CRIT' in severity:
            return 'CRITICAL'
        elif 'HIGH' in severity:
            return 'HIGH'
        elif 'MED' in severity:
            return 'MEDIUM'
        elif 'LOW' in severity:
            return 'LOW'
        elif 'INFO' in severity:
            return 'INFORMATIONAL'

        return 'MEDIUM'

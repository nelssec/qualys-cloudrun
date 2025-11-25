"""
Container image name parser
Handles various image name formats from different registries
"""
import re
from typing import Dict


class ImageParserError(Exception):
    """Raised when image parsing fails due to invalid input"""
    pass


class ImageParser:
    """
    Parse container image names into components
    Supports Docker Hub, Google Container Registry, Artifact Registry, and other registries
    """

    # Security: Allowlist of valid characters for image components
    # Based on OCI distribution spec and Docker naming conventions
    VALID_REGISTRY_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?)*(:[0-9]+)?$')
    VALID_REPOSITORY_PATTERN = re.compile(r'^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$')
    VALID_TAG_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$')
    VALID_DIGEST_PATTERN = re.compile(r'^sha256:[a-f0-9]{64}$')

    # Maximum lengths to prevent DoS
    MAX_IMAGE_NAME_LENGTH = 512
    MAX_REGISTRY_LENGTH = 253  # DNS hostname limit
    MAX_REPOSITORY_LENGTH = 256
    MAX_TAG_LENGTH = 128

    @classmethod
    def validate_image_name(cls, image_name: str) -> bool:
        """
        Validate image name for security

        Args:
            image_name: Full image name to validate

        Returns:
            True if valid, raises ImageParserError if invalid
        """
        if not image_name or not isinstance(image_name, str):
            raise ImageParserError("Image name must be a non-empty string")

        if len(image_name) > cls.MAX_IMAGE_NAME_LENGTH:
            raise ImageParserError(f"Image name exceeds maximum length of {cls.MAX_IMAGE_NAME_LENGTH}")

        # Check for shell injection characters
        dangerous_chars = ['$', '`', ';', '&', '|', '>', '<', '\n', '\r', '\0', '\\']
        for char in dangerous_chars:
            if char in image_name:
                raise ImageParserError(f"Image name contains invalid character: {repr(char)}")

        return True

    @classmethod
    def parse(cls, image_name: str) -> Dict:
        """
        Parse a container image name into components

        Args:
            image_name: Full image name (e.g., docker.io/library/nginx:latest)

        Returns:
            Dictionary with parsed components:
                - registry: Registry hostname
                - repository: Repository path
                - tag: Image tag
                - digest: Image digest (if present)
                - full_name: Complete image identifier

        Raises:
            ImageParserError: If the image name is invalid or contains dangerous characters

        Examples:
            nginx -> docker.io/library/nginx:latest
            gcr.io/project/app:v1 -> gcr.io/project/app:v1
            us-docker.pkg.dev/project/repo/app:latest -> us-docker.pkg.dev/project/repo/app:latest
            nginx@sha256:abc123 -> docker.io/library/nginx@sha256:abc123
        """
        # Security: Validate input before parsing
        cls.validate_image_name(image_name)

        original_name = image_name

        # Handle digest format (image@sha256:...)
        digest = None
        if '@sha256:' in image_name:
            image_name, digest_hash = image_name.split('@sha256:', 1)
            digest = f'sha256:{digest_hash}'

            # Validate digest format
            if not cls.VALID_DIGEST_PATTERN.match(digest):
                raise ImageParserError(f"Invalid digest format: {digest}")

        # Split tag from image name
        tag = 'latest'
        if ':' in image_name:
            image_name, tag = image_name.rsplit(':', 1)

        # Validate tag
        if not cls.VALID_TAG_PATTERN.match(tag):
            raise ImageParserError(f"Invalid tag format: {tag}")

        if len(tag) > cls.MAX_TAG_LENGTH:
            raise ImageParserError(f"Tag exceeds maximum length of {cls.MAX_TAG_LENGTH}")

        # Parse registry and repository
        parts = image_name.split('/')

        if len(parts) == 1:
            # Simple name like "nginx"
            registry = 'docker.io'
            repository = f'library/{parts[0]}'
        elif len(parts) == 2:
            # Could be "user/repo" or "registry/repo"
            if '.' in parts[0] or ':' in parts[0]:
                # Has registry (contains . or port)
                registry = parts[0]
                repository = parts[1]
            else:
                # Docker Hub user repository
                registry = 'docker.io'
                repository = f'{parts[0]}/{parts[1]}'
        else:
            # Full path with registry
            registry = parts[0]
            repository = '/'.join(parts[1:])

        # Validate registry
        if len(registry) > cls.MAX_REGISTRY_LENGTH:
            raise ImageParserError(f"Registry exceeds maximum length of {cls.MAX_REGISTRY_LENGTH}")

        # Validate repository length
        if len(repository) > cls.MAX_REPOSITORY_LENGTH:
            raise ImageParserError(f"Repository exceeds maximum length of {cls.MAX_REPOSITORY_LENGTH}")

        # Construct full name
        full_name = f'{registry}/{repository}:{tag}'
        if digest:
            full_name = f'{registry}/{repository}@{digest}'

        return {
            'registry': registry,
            'repository': repository,
            'tag': tag,
            'digest': digest,
            'full_name': full_name,
            'original': original_name
        }

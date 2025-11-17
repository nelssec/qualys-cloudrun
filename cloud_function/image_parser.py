"""
Container image name parser
Handles various image name formats from different registries
"""
from typing import Dict


class ImageParser:
    """
    Parse container image names into components
    Supports Docker Hub, Google Container Registry, Artifact Registry, and other registries
    """

    @staticmethod
    def parse(image_name: str) -> Dict:
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

        Examples:
            nginx -> docker.io/library/nginx:latest
            gcr.io/project/app:v1 -> gcr.io/project/app:v1
            us-docker.pkg.dev/project/repo/app:latest -> us-docker.pkg.dev/project/repo/app:latest
            nginx@sha256:abc123 -> docker.io/library/nginx@sha256:abc123
        """
        # Handle digest format (image@sha256:...)
        digest = None
        if '@sha256:' in image_name:
            image_name, digest = image_name.split('@sha256:')
            digest = f'sha256:{digest}'

        # Split tag from image name
        tag = 'latest'
        if ':' in image_name:
            image_name, tag = image_name.rsplit(':', 1)

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
            'original': image_name if not digest else f'{image_name}@{digest}'
        }

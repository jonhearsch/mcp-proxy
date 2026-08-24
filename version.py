"""
Version management for MCP Proxy Server.

This file contains the current version number and is automatically updated
by the CI/CD pipeline during builds.
"""

__version__ = "3.0.7"
__build__ = "8228d5fbb68cde962cd9caf8272682fe5cc8eebe"

def get_version():
    """Get the full version string including build info.
    
    Returns a consistent semver build-metadata format:
      3.0.3+dev          (local development)
      3.0.3+a17d82e...   (CI build with commit SHA)
    """
    return f"{__version__}+{__build__}"

def get_version_info():
    """Get version information as a dictionary."""
    major, minor, patch = __version__.split('.')
    return {
        'major': int(major),
        'minor': int(minor),
        'patch': int(patch),
        'build': __build__,
        'full': get_version()
    }

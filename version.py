"""
Version management for MCP Proxy Server.

This file contains the current version number and is automatically updated
by the CI/CD pipeline during builds.
"""

__version__ = "2.0.1"
__build__ = "ae3ab09d4668429aa8cab57e036cf204645dca1a"

def get_version():
    """Get the full version string including build info."""
    if __build__ == "dev":
        return f"{__version__}-dev"
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

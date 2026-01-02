"""
Version management for MCP Proxy Server.

This file contains the current version number and is automatically updated
by the CI/CD pipeline during builds.
"""

__version__ = "2.0.8"
__build__ = "70caabffa1fbc8f50bf7b04a4e1c8757975d61f7"

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

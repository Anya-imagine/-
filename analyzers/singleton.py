"""
This module manages singleton instances to avoid circular imports.
"""

from .field import FieldManager

# Initialize field_manager directly
field_manager = FieldManager()

def init_singletons():
    """Initialize all singleton instances after imports are complete."""
    # field_manager is already initialized
    pass 
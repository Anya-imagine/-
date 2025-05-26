"""
This module manages singleton instances to avoid circular imports.
"""

# Initialize as None, will be set after imports are complete
field_manager = None

def init_singletons():
    """Initialize all singleton instances after imports are complete."""
    from .field import FieldManager
    global field_manager
    field_manager = FieldManager() 
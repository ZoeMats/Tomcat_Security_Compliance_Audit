###__init__.py`**

"""
Defines the tomcat_scanner package and controls what gets imported when using the package.
Specifies package metadata (version number, info of author)
Imports main classes (TomcatComplianceScanner, ScannerConfig) to make them accessible at package level
"""
__version__ = "1.0.0"
__author__ = "Zoi"

from .scanner import TomcatComplianceScanner
from .config import ScannerConfig

__all__ = ['TomcatComplianceScanner', 'ScannerConfig']

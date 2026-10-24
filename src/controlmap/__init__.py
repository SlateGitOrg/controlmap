"""controlmap: SOC 2 evidence automation.

Collect evidence from files or mocked APIs, evaluate it against a control library mapped
to SOC 2 Trust Services Criteria (with an ISO/IEC 27001:2022 Annex A crosswalk), track
exceptions, and build a hashed, verifiable evidence package for auditors.

controlmap supports an audit; it does not replace one.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]

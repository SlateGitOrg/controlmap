"""Built-in rules. Importing this package registers them."""

from . import cloud, documents, endpoint, github, identity, people
from .base import Param, RuleContext, RuleOutcome, RuleSpec, get_rule, rule, rule_registry

__all__ = [
    "Param",
    "RuleContext",
    "RuleOutcome",
    "RuleSpec",
    "cloud",
    "documents",
    "endpoint",
    "get_rule",
    "github",
    "identity",
    "people",
    "rule",
    "rule_registry",
]

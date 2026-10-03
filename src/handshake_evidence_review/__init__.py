"""Defensive capture evidence without sample execution or live collection."""

from .contracts import Limits, encode_report
from .review import review_bytes

__version__ = "0.1.1"
__all__ = ["Limits", "encode_report", "review_bytes"]

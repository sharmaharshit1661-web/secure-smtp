"""
JSON report exporter.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def generate_json_report(report_data: dict, output_path: str) -> str:
    """
    Generate a JSON report from the analysis data.

    Args:
        report_data: Complete report data structure.
        output_path: Path to write the JSON file.

    Returns:
        Path to the generated file.
    """
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    with open(output, "w") as f:
        json.dump(report_data, f, indent=2, default=str)

    logger.info("Generated JSON report: %s", output)
    return str(output)

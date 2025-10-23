import json
import magic
from pathlib import Path
from typing import Optional, Tuple
import xml.etree.ElementTree as ET
import csv
import io

from models import InputFormat


class InputDetector:
    """Detects and validates input formats for fuzzing."""

    def __init__(self):
        try:
            self.magic = magic.Magic(mime=True)
        except Exception:
            self.magic = None

    def detect_format(self, sample_file: str) -> InputFormat:
        """
        Detect the format of the sample input file.

        Args:
            sample_file: Path to the sample input file

        Returns:
            Detected InputFormat

        Raises:
            ValueError: If format cannot be detected or is unsupported
        """
        file_path = Path(sample_file)
        if not file_path.exists():
            raise ValueError(f"Sample file does not exist: {sample_file}")

        try:
            with open(file_path, "rb") as f:
                content = f.read()
        except Exception as e:
            raise ValueError(f"Could not read sample file: {e}")

        # Debug: print content info
        content_str = content.decode("utf-8", errors="ignore")
        print(f"[DEBUG] File: {file_path.name}, Content: {repr(content_str[:50])}, Extension: {file_path.suffix}")

        format_result = self._detect_by_magic_numbers(content)
        if format_result:
            print(f"[DEBUG] Detected by magic numbers: {format_result}")
            return format_result

        format_result = self._detect_by_content(content, file_path.suffix)
        if format_result:
            print(f"[DEBUG] Detected by content: {format_result}")
            return format_result

        format_result = self._detect_by_extension(file_path.suffix)
        if format_result:
            print(f"[DEBUG] Detected by extension: {format_result}")
            return format_result

        print(f"[DEBUG] Defaulting to PLAINTEXT")
        return InputFormat.PLAINTEXT

    def _detect_by_magic_numbers(self, content: bytes) -> Optional[InputFormat]:
        """Detect format by checking magic numbers/signatures."""
        if len(content) < 4:
            return None

        if content.startswith(b"\xff\xd8\xff"):
            return InputFormat.JPEG

        if content.startswith(b"\x7fELF"):
            return InputFormat.ELF

        if content.startswith(b"%PDF"):
            return InputFormat.PDF

        return None

    def _detect_by_content(
        self, content: bytes, extension: str
    ) -> Optional[InputFormat]:
        """Detect format by attempting to parse content."""
        try:
            # Try JSON
            content_str = content.decode("utf-8", errors="ignore").strip()
            if content_str.startswith(("{", "[")):
                json.loads(content_str)
                return InputFormat.JSON

            # Try XML (only valid XML)
            if content_str.startswith("<?xml") or (
                content_str.startswith("<") and
                content_str.find(">") > 1 and
                content_str.find("</") > content_str.find(">")  # Has closing tag
            ):
                try:
                    ET.fromstring(content_str)
                    return InputFormat.XML
                except ET.ParseError:
                    pass  # Not valid XML, continue to other detection

            # Try CSV (heuristic detection)
            if self._looks_like_csv(content_str):
                return InputFormat.CSV

        except (json.JSONDecodeError, ET.ParseError, UnicodeDecodeError):
            pass

        return None

    def _detect_by_extension(self, extension: str) -> Optional[InputFormat]:
        """Detect format by file extension."""
        extension = extension.lower()

        extension_map = {
            ".json": InputFormat.JSON,
            ".xml": InputFormat.XML,
            ".csv": InputFormat.CSV,
            ".jpg": InputFormat.JPEG,
            ".jpeg": InputFormat.JPEG,
            ".elf": InputFormat.ELF,
            ".pdf": InputFormat.PDF,
            ".txt": InputFormat.PLAINTEXT,
            ".text": InputFormat.PLAINTEXT,
        }

        return extension_map.get(extension)

    def _looks_like_csv(self, content: str) -> bool:
        """Heuristic check if content looks like CSV."""
        try:
            reader = csv.reader(io.StringIO(content))
            rows = list(reader)

            if len(rows) < 2:
                return False

            first_row_cols = len(rows[0])
            for row in rows[1:]:
                if len(row) != first_row_cols:
                    return False

            return first_row_cols >= 2

        except Exception:
            return False

    def validate_format(self, content: bytes, expected_format: InputFormat) -> bool:
        """
        Validate that content matches the expected format.

        Args:
            content: Content to validate
            expected_format: Expected format

        Returns:
            True if content matches expected format, False otherwise
        """
        try:
            if expected_format == InputFormat.JSON:
                content_str = content.decode("utf-8")
                json.loads(content_str)
                return True

            elif expected_format == InputFormat.XML:
                content_str = content.decode("utf-8")
                ET.fromstring(content_str)
                return True

            elif expected_format == InputFormat.CSV:
                content_str = content.decode("utf-8")
                reader = csv.reader(io.StringIO(content_str))
                rows = list(reader)
                return len(rows) > 0 and len(rows[0]) > 0

            elif expected_format == InputFormat.JPEG:
                return content.startswith(b"\xff\xd8\xff")

            elif expected_format == InputFormat.ELF:
                return content.startswith(b"\x7fELF")

            elif expected_format == InputFormat.PDF:
                return content.startswith(b"%PDF")

            elif expected_format == InputFormat.PLAINTEXT:
                content.decode("utf-8")
                return True

        except Exception:
            pass

        return False

    def get_format_info(self, input_format: InputFormat) -> dict:
        """
        Get information about a supported format.

        Args:
            input_format: The format to get info for

        Returns:
            Dictionary with format information
        """
        format_info = {
            InputFormat.JSON: {
                "name": "JavaScript Object Notation",
                "description": "Structured data format with key-value pairs",
                "typical_mutations": [
                    "Invalid JSON structure",
                    "Type confusion",
                    "Nesting limits",
                ],
            },
            InputFormat.XML: {
                "name": "eXtensible Markup Language",
                "description": "Markup language with nested elements",
                "typical_mutations": [
                    "Malformed tags",
                    "Entity expansion",
                    "Attribute injection",
                ],
            },
            InputFormat.CSV: {
                "name": "Comma-Separated Values",
                "description": "Tabular data with comma-separated fields",
                "typical_mutations": [
                    "Field count changes",
                    "Type injection",
                    "Delimiter confusion",
                ],
            },
            InputFormat.JPEG: {
                "name": "JPEG Image",
                "description": "Compressed image format",
                "typical_mutations": [
                    "Corrupted headers",
                    "Invalid dimensions",
                    "Buffer overflows",
                ],
            },
            InputFormat.ELF: {
                "name": "Executable and Linkable Format",
                "description": "Linux executable format",
                "typical_mutations": [
                    "Invalid sections",
                    "Corrupted headers",
                    "Bad symbols",
                ],
            },
            InputFormat.PDF: {
                "name": "Portable Document Format",
                "description": "Document format with embedded objects",
                "typical_mutations": [
                    "Invalid objects",
                    "Stream corruption",
                    "Filter injection",
                ],
            },
            InputFormat.PLAINTEXT: {
                "name": "Plain Text",
                "description": "Unformatted text data",
                "typical_mutations": [
                    "Buffer overflows",
                    "Format strings",
                    "Encoding issues",
                ],
            },
        }

        return format_info.get(
            input_format, {"name": "Unknown", "description": "Unsupported format"}
        )


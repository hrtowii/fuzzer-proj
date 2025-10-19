import random
from typing import List, Dict, Any, Optional

from .base import MutationStrategy


class StructureModificationStrategy(MutationStrategy):
    """
    Structure modification strategy that alters the structure and format of input data.
    This is particularly effective for structured formats like JSON, XML, CSV, etc.
    """

    def __init__(self):
        """Initialize the structure modification strategy."""
        super().__init__("Structure Modification")
        self.modification_types = [
            "truncation",
            "expansion",
            "reordering",
            "duplication",
            "nesting",
            "flattening",
            "boundary_manipulation",
        ]

    def apply(self, data: bytes) -> bytes:
        """
        Apply structure modification mutations.

        Args:
            data: Original input data

        Returns:
            Data with structural modifications applied
        """
        if not data:
            return self._generate_random_structure()

        modification_type = random.choice(self.modification_types)

        if modification_type == "truncation":
            return self._truncate_structure(data)
        elif modification_type == "expansion":
            return self._expand_structure(data)
        elif modification_type == "reordering":
            return self._reorder_structure(data)
        elif modification_type == "duplication":
            return self._duplicate_structure(data)
        elif modification_type == "nesting":
            return self._nest_structure(data)
        elif modification_type == "flattening":
            return self._flatten_structure(data)
        else:  # boundary_manipulation
            return self._manipulate_boundaries(data)

    def _truncate_structure(self, data: bytes) -> bytes:
        """Truncate the structure at various points."""
        if len(data) <= 1:
            return data

        # Choose truncation strategy
        strategy = random.choice(
            [
                "early_truncate",  # Truncate early
                "late_truncate",  # Truncate near end
                "middle_truncate",  # Truncate in middle
                "boundary_truncate",  # Truncate at boundary
            ]
        )

        if strategy == "early_truncate":
            truncate_point = random.randint(1, min(len(data) // 4, 10))
        elif strategy == "late_truncate":
            truncate_point = random.randint(max(1, len(data) - 10), len(data) - 1)
        elif strategy == "middle_truncate":
            truncate_point = len(data) // 2 + random.randint(-5, 5)
        else:  # boundary_truncate
            # Look for common boundary characters
            boundary_chars = [b"\n", b"\r", b"\t", b" ", b",", b";", b"}", b"]", b")"]
            truncate_point = len(data) - 1

            for char in boundary_chars:
                pos = data.rfind(char)
                if pos != -1:
                    truncate_point = min(truncate_point, pos)

        return data[: max(1, truncate_point)]

    def _expand_structure(self, data: bytes) -> bytes:
        """Expand the structure by adding content."""
        try:
            text_data = data.decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            return data + b"A" * 100

        expansion_type = random.choice(
            ["repeat_content", "pad_content", "add_delimiters", "expand_fields"]
        )

        if expansion_type == "repeat_content":
            # Repeat the entire content
            repeat_count = random.randint(2, 5)
            return data * repeat_count

        elif expansion_type == "pad_content":
            # Add padding
            padding_type = random.choice(["nulls", "spaces", "random"])
            if padding_type == "nulls":
                padding = b"\x00" * random.randint(50, 500)
            elif padding_type == "spaces":
                padding = b" " * random.randint(50, 500)
            else:
                padding = bytes(
                    [random.randint(32, 126) for _ in range(random.randint(50, 500))]
                )

            if random.random() < 0.5:
                return padding + data
            else:
                return data + padding

        elif expansion_type == "add_delimiters":
            # Add delimiter characters
            delimiters = [b"\n", b"\r\n", b",", b";", b" ", b"\t"]
            delimiter = random.choice(delimiters)
            multiplier = random.randint(10, 100)
            return data + (delimiter * multiplier)

        else:  # expand_fields
            # Try to expand structured fields
            if "{" in text_data and "}" in text_data:  # JSON-like
                return self._expand_json_like(data)
            elif "<" in text_data and ">" in text_data:  # XML-like
                return self._expand_xml_like(data)
            elif "," in text_data:  # CSV-like
                return self._expand_csv_like(data)
            else:
                return data + b",extra_field=value"

    def _reorder_structure(self, data: bytes) -> bytes:
        """Reorder parts of the structure."""
        try:
            text_data = data.decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            # For binary data, just shuffle chunks
            chunk_size = min(100, len(data) // 4)
            if chunk_size > 0:
                chunks = [
                    data[i : i + chunk_size] for i in range(0, len(data), chunk_size)
                ]
                random.shuffle(chunks)
                return b"".join(chunks)
            return data

        # Try to detect structure and reorder
        if "{" in text_data and "}" in text_data:
            return self._reorder_json_like(data)
        elif "<" in text_data and ">" in text_data:
            return self._reorder_xml_like(data)
        elif "\n" in text_data:
            # Reorder lines
            lines = text_data.split("\n")
            if len(lines) > 1:
                random.shuffle(lines[1:-1])  # Keep first and last
                return "\n".join(lines).encode("utf-8")

        return data

    def _duplicate_structure(self, data: bytes) -> bytes:
        """Duplicate parts of the structure."""
        try:
            text_data = data.decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            # Duplicate binary chunks
            if len(data) > 10:
                chunk_size = random.randint(1, min(50, len(data) // 2))
                chunk_start = random.randint(0, len(data) - chunk_size)
                chunk = data[chunk_start : chunk_start + chunk_size]
                insert_pos = random.randint(0, len(data))
                result = bytearray(data)
                result[insert_pos:insert_pos] = chunk
                return bytes(result)
            return data * 2

        # Duplicate structured elements
        if "{" in text_data and "}" in text_data:
            return self._duplicate_json_element(data)
        elif "<" in text_data and ">" in text_data:
            return self._duplicate_xml_element(data)
        elif "\n" in text_data:
            # Duplicate lines
            lines = text_data.split("\n")
            if len(lines) > 1:
                line_to_dup = random.choice(lines[1:-1])  # Don't duplicate first/last
                insert_pos = random.randint(1, len(lines) - 1)
                lines.insert(insert_pos, line_to_dup)
                return "\n".join(lines).encode("utf-8")

        return data

    def _nest_structure(self, data: bytes) -> bytes:
        """Create nested structures."""
        try:
            text_data = data.decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            return b"{" + data + b"}"

        nesting_type = random.choice(["wrap_object", "wrap_array", "deep_nest"])

        if nesting_type == "wrap_object":
            # Wrap in object
            if text_data.startswith("{"):
                return f'{{"nested":{text_data}}}'.encode("utf-8")
            else:
                return f'{{"data":"{text_data}"}}'.encode("utf-8")

        elif nesting_type == "wrap_array":
            # Wrap in array
            if text_data.startswith("["):
                return f"[{text_data}]".encode("utf-8")
            else:
                return f'["{text_data}"]'.encode("utf-8")

        else:  # deep_nest
            # Create deep nesting
            result = text_data
            depth = random.randint(3, 10)
            for i in range(depth):
                if random.random() < 0.5:
                    result = f'{{"level_{i}":{result}}}'
                else:
                    result = f"[{result}]"
            return result.encode("utf-8")

    def _flatten_structure(self, data: bytes) -> bytes:
        """Flatten nested structures."""
        try:
            text_data = data.decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            return data

        # Simple flattening - remove common structural characters
        flattening_rules = [
            lambda x: x.replace("{", "").replace("}", ""),
            lambda x: x.replace("[", "").replace("]", ""),
            lambda x: x.replace('"', ""),
            lambda x: x.replace("\n", " ").replace("\r", ""),
            lambda x: x.replace("\t", " "),
        ]

        rule = random.choice(flattening_rules)
        return rule(text_data).encode("utf-8")

    def _manipulate_boundaries(self, data: bytes) -> bytes:
        """Manipulate structural boundaries."""
        if len(data) < 2:
            return data

        manipulation_type = random.choice(
            [
                "remove_delimiters",
                "add_delimiters",
                "duplicate_delimiters",
                "corrupt_boundaries",
            ]
        )

        try:
            text_data = data.decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            manipulation_type = "corrupt_boundaries"

        if manipulation_type == "remove_delimiters":
            # Remove structural delimiters
            delimiters = ["\n", "\r", "\t", ",", ";", " ", "{", "}", "[", "]", '"', "'"]
            delimiter = random.choice(delimiters)
            return text_data.replace(delimiter, "").encode("utf-8")

        elif manipulation_type == "add_delimiters":
            # Add extra delimiters
            delimiters = ["\n", ",", ";", " ", "\t"]
            delimiter = random.choice(delimiters)
            multiplier = random.randint(5, 20)
            return (delimiter * multiplier).encode("utf-8") + data

        elif manipulation_type == "duplicate_delimiters":
            # Duplicate existing delimiters
            delimiters = ["\n", ",", ";", " ", "\t"]
            for delim in delimiters:
                if delim in text_data:
                    return text_data.replace(delim, delim * 2).encode("utf-8")
            return data

        else:  # corrupt_boundaries
            # Corrupt boundary bytes
            result = bytearray(data)
            corruption_count = random.randint(1, min(10, len(result) // 10))
            for _ in range(corruption_count):
                pos = random.randint(0, len(result) - 1)
                result[pos] = random.randint(0, 255)
            return bytes(result)

    def _generate_random_structure(self) -> bytes:
        """Generate a random structured input."""
        structure_type = random.choice(["json", "xml", "csv", "key_value"])

        if structure_type == "json":
            return self._generate_random_json()
        elif structure_type == "xml":
            return self._generate_random_xml()
        elif structure_type == "csv":
            return self._generate_random_csv()
        else:  # key_value
            return self._generate_random_key_value()

    def _generate_random_json(self) -> bytes:
        """Generate random JSON structure."""
        num_fields = random.randint(1, 10)
        fields = []

        for i in range(num_fields):
            field_type = random.choice(
                ["string", "number", "boolean", "null", "object", "array"]
            )
            field_name = f"field_{i}"

            if field_type == "string":
                value = f'"value_{i}"'
            elif field_type == "number":
                value = str(random.randint(-1000, 1000))
            elif field_type == "boolean":
                value = str(random.choice([True, False])).lower()
            elif field_type == "null":
                value = "null"
            elif field_type == "object":
                value = '{"nested": "value"}'
            else:  # array
                value = f"[{'value_1'}]"

            fields.append(f'"{field_name}": {value}')

        return f"{{{', '.join(fields)}}}".encode("utf-8")

    def _generate_random_xml(self) -> bytes:
        """Generate random XML structure."""
        num_elements = random.randint(1, 10)
        xml = "<root>"

        for i in range(num_elements):
            element_name = f"element_{i}"
            content = f"content_{i}"
            xml += f"<{element_name}>{content}</{element_name}>"

        xml += "</root>"
        return xml.encode("utf-8")

    def _generate_random_csv(self) -> bytes:
        """Generate random CSV structure."""
        num_rows = random.randint(2, 10)
        num_cols = random.randint(2, 5)

        # Header
        header = ",".join([f"col_{i}" for i in range(num_cols)])

        # Data rows
        rows = [header]
        for row_idx in range(num_rows):
            row = ",".join(
                [f"value_{row_idx}_{col_idx}" for col_idx in range(num_cols)]
            )
            rows.append(row)

        return "\n".join(rows).encode("utf-8")

    def _generate_random_key_value(self) -> bytes:
        """Generate random key-value structure."""
        num_pairs = random.randint(1, 10)
        pairs = []

        for i in range(num_pairs):
            key = f"key_{i}"
            value = f"value_{i}"
            pairs.append(f"{key}={value}")

        return "&".join(pairs).encode("utf-8")

    # Helper methods for specific format handling
    def _expand_json_like(self, data: bytes) -> bytes:
        """Expand JSON-like structures."""
        try:
            text_data = data.decode("utf-8", errors="ignore")
            # Add extra fields
            return (text_data.rstrip("}") + ', "extra_field": "extra_value"}').encode(
                "utf-8"
            )
        except:
            return data + b",extra=value"

    def _expand_xml_like(self, data: bytes) -> bytes:
        """Expand XML-like structures."""
        try:
            text_data = data.decode("utf-8", errors="ignore")
            # Add extra element before closing tag
            insert_pos = text_data.rfind("</")
            if insert_pos != -1:
                return (
                    text_data[:insert_pos]
                    + "<extra>value</extra>"
                    + text_data[insert_pos:]
                ).encode("utf-8")
        except:
            pass
        return data + b"<extra>value</extra>"

    def _expand_csv_like(self, data: bytes) -> bytes:
        """Expand CSV-like structures."""
        try:
            text_data = data.decode("utf-8", errors="ignore")
            lines = text_data.split("\n")
            if lines:
                # Add extra column
                first_line = lines[0]
                num_cols = first_line.count(",") + 1
                extra_cols = ",extra_value" * random.randint(1, 3)
                return (text_data + extra_cols).encode("utf-8")
        except:
            pass
        return data + b",extra"

    def _reorder_json_like(self, data: bytes) -> bytes:
        """Reorder JSON-like fields."""
        try:
            text_data = data.decode("utf-8", errors="ignore")
            # Simple field reordering (basic approach)
            # This is a simplified implementation
            return text_data.encode("utf-8")  # Keep as-is for now
        except:
            return data

    def _reorder_xml_like(self, data: bytes) -> bytes:
        """Reorder XML-like elements."""
        try:
            text_data = data.decode("utf-8", errors="ignore")
            # Simple element reordering (basic approach)
            return text_data.encode("utf-8")  # Keep as-is for now
        except:
            return data

    def _duplicate_json_element(self, data: bytes) -> bytes:
        """Duplicate a JSON element."""
        try:
            text_data = data.decode("utf-8", errors="ignore")
            # Find and duplicate a field
            if ":" in text_data:
                parts = text_data.split(":", 1)
                if len(parts) == 2:
                    field = parts[0] + ":" + parts[1].split(",")[0]
                    return (text_data + "," + field).encode("utf-8")
        except:
            pass
        return data * 2

    def _duplicate_xml_element(self, data: bytes) -> bytes:
        """Duplicate an XML element."""
        try:
            text_data = data.decode("utf-8", errors="ignore")
            # Find and duplicate an element
            if "<" in text_data and ">" in text_data:
                start = text_data.find("<")
                end = text_data.find(">", start)
                if start != -1 and end != -1:
                    element = text_data[start : end + 1]
                    end_element = element.replace("<", "</")
                    full_element = element + "content" + end_element
                    return (text_data + full_element).encode("utf-8")
        except:
            pass
        return data * 2

    def get_description(self) -> str:
        """Get a description of the structure modification strategy."""
        return "Modifies the structure and format of input data"

    def get_effectiveness_score(self) -> float:
        """Highly effective for structured format parsing vulnerabilities."""
        return 0.8

    def get_complexity_score(self) -> float:
        """Higher complexity due to structure analysis."""
        return 0.6


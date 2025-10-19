import struct
import random
from typing import Optional, List, Tuple

from .base import BaseMutator
from models import InputFormat


class BinaryMutator(BaseMutator):
    """
    Binary mutator for handling JPEG, ELF, PDF, and other binary formats.
    Applies mutations at the byte level while attempting to preserve some structure.
    """

    def __init__(self, sample_data: bytes, input_format: InputFormat):
        """
        Initialize binary mutator with sample data.

        Args:
            sample_data: Original binary data
            input_format: Specific binary format (JPEG, ELF, PDF, etc.)
        """
        super().__init__(sample_data, input_format)
        self._format_specific_mutators = {
            InputFormat.JPEG: self._mutate_jpeg,
            InputFormat.ELF: self._mutate_elf,
            InputFormat.PDF: self._mutate_pdf,
        }

    def mutate(self) -> bytes:
        """
        Generate a mutated binary by applying various mutation strategies.

        Returns:
            Mutated binary data
        """
        # Use format-specific mutator if available
        if self.input_format in self._format_specific_mutators:
            return self._format_specific_mutators[self.input_format]()

        # Generic binary mutations
        mutation_type = self.random.choice(
            [
                "byte_bit_flips",
                "arithmetic_mutations",
                "insertion_deletion",
                "boundary_mutations",
                "magic_number_mutation",
                "structure_aware_mutation",
            ]
        )

        if mutation_type == "byte_bit_flips":
            return self._byte_bit_flip_mutation()
        elif mutation_type == "arithmetic_mutations":
            return self._arithmetic_mutation()
        elif mutation_type == "insertion_deletion":
            return self._insertion_deletion_mutation()
        elif mutation_type == "boundary_mutations":
            return self._boundary_mutation()
        elif mutation_type == "magic_number_mutation":
            return self._magic_number_mutation()
        else:  # structure_aware_mutation
            return self._structure_aware_mutation()

    def _mutate_jpeg(self) -> bytes:
        """Apply JPEG-specific mutations."""
        if not self._is_valid_jpeg():
            return self._generic_binary_mutation()

        mutation_type = self.random.choice(
            [
                "header_corruption",
                "quantization_mutation",
                "huffman_mutation",
                "dimension_mutation",
                "comment_injection",
                "marker_corruption",
            ]
        )

        if mutation_type == "header_corruption":
            return self._corrupt_jpeg_header()
        elif mutation_type == "quantization_mutation":
            return self._mutate_jpeg_quantization()
        elif mutation_type == "huffman_mutation":
            return self._mutate_jpeg_huffman()
        elif mutation_type == "dimension_mutation":
            return self._mutate_jpeg_dimensions()
        elif mutation_type == "comment_injection":
            return self._inject_jpeg_comment()
        else:  # marker_corruption
            return self._corrupt_jpeg_markers()

    def _mutate_elf(self) -> bytes:
        """Apply ELF-specific mutations."""
        if not self._is_valid_elf():
            return self._generic_binary_mutation()

        mutation_type = self.random.choice(
            [
                "header_corruption",
                "section_mutation",
                "segment_mutation",
                "symbol_corruption",
                "relocation_mutation",
                "entry_point_mutation",
            ]
        )

        if mutation_type == "header_corruption":
            return self._corrupt_elf_header()
        elif mutation_type == "section_mutation":
            return self._mutate_elf_sections()
        elif mutation_type == "segment_mutation":
            return self._mutate_elf_segments()
        elif mutation_type == "symbol_corruption":
            return self._corrupt_elf_symbols()
        elif mutation_type == "relocation_mutation":
            return self._mutate_elf_relocations()
        else:  # entry_point_mutation
            return self._mutate_elf_entry_point()

    def _mutate_pdf(self) -> bytes:
        """Apply PDF-specific mutations."""
        if not self._is_valid_pdf():
            return self._generic_binary_mutation()

        mutation_type = self.random.choice(
            [
                "header_corruption",
                "xref_mutation",
                "object_mutation",
                "stream_corruption",
                "filter_mutation",
                "trailer_mutation",
            ]
        )

        if mutation_type == "header_corruption":
            return self._corrupt_pdf_header()
        elif mutation_type == "xref_mutation":
            return self._mutate_pdf_xref()
        elif mutation_type == "object_mutation":
            return self._mutate_pdf_objects()
        elif mutation_type == "stream_corruption":
            return self._corrupt_pdf_streams()
        elif mutation_type == "filter_mutation":
            return self._mutate_pdf_filters()
        else:  # trailer_mutation
            return self._mutate_pdf_trailer()

    def _generic_binary_mutation(self) -> bytes:
        """Apply generic binary mutations when format-specific ones aren't available."""
        mutation_type = self.random.choice(
            [
                "byte_bit_flips",
                "arithmetic_mutations",
                "insertion_deletion",
                "boundary_mutations",
            ]
        )

        if mutation_type == "byte_bit_flips":
            return self._byte_bit_flip_mutation()
        elif mutation_type == "arithmetic_mutations":
            return self._arithmetic_mutation()
        elif mutation_type == "insertion_deletion":
            return self._insertion_deletion_mutation()
        else:  # boundary_mutations
            return self._boundary_mutation()

    def _byte_bit_flip_mutation(self) -> bytes:
        """Apply bit flip mutations to the binary data."""
        if not self.current_data:
            return self.current_data

        # Choose mutation intensity
        intensity = self.random.choice(["light", "medium", "heavy"])

        if intensity == "light":
            probability = 0.001  # 0.1% of bits
        elif intensity == "medium":
            probability = 0.01  # 1% of bits
        else:  # heavy
            probability = 0.1  # 10% of bits

        return self._bit_flip(self.current_data, probability)

    def _arithmetic_mutation(self) -> bytes:
        """Apply arithmetic mutations to numeric values in the binary."""
        if not self.current_data or len(self.current_data) < 4:
            return self.current_data

        return self._arithmetic_mutations(self.current_data)

    def _insertion_deletion_mutation(self) -> bytes:
        """Apply byte insertion and deletion mutations."""
        if not self.current_data:
            return self.current_data

        mutation_type = self.random.choice(["insertion", "deletion", "both"])

        if mutation_type == "insertion":
            return self._byte_insertion(self.current_data)
        elif mutation_type == "deletion":
            return self._byte_deletion(self.current_data)
        else:  # both
            data = self._byte_insertion(self.current_data)
            return self._byte_deletion(data)

    def _boundary_mutation(self) -> bytes:
        """Apply boundary-related mutations."""
        return self._boundary_mutations(self.current_data)

    def _magic_number_mutation(self) -> bytes:
        """Mutate magic numbers/signatures in the binary."""
        if not self.current_data or len(self.current_data) < 4:
            return self.current_data

        result = bytearray(self.current_data)

        # Known magic numbers to potentially corrupt
        magic_signatures = [
            b"\xff\xd8\xff",  # JPEG
            b"\x7fELF",  # ELF
            b"%PDF",  # PDF
            b"GIF8",  # GIF
            b"\x89PNG",  # PNG
            b"PK\x03\x04",  # ZIP
        ]

        for signature in magic_signatures:
            if result.startswith(signature):
                # Corrupt the magic number
                if self.random.random() < 0.5:
                    # Flip bits in magic number
                    for i in range(min(len(signature), 4)):
                        if self.random.random() < 0.3:
                            result[i] ^= 1 << self.random.randint(0, 7)
                else:
                    # Replace with random bytes
                    for i in range(min(len(signature), 4)):
                        result[i] = self.random.randint(0, 255)
                break

        return bytes(result)

    def _structure_aware_mutation(self) -> bytes:
        """Apply mutations that are somewhat structure-aware."""
        if not self.current_data:
            return self.current_data

        # Try to identify and mutate structure-like patterns
        mutation_type = self.random.choice(
            ["repeat_pattern", "swap_chunks", "corrupt_checksum", "null_injection"]
        )

        if mutation_type == "repeat_pattern":
            return self._repeat_patterns()
        elif mutation_type == "swap_chunks":
            return self._swap_chunks()
        elif mutation_type == "corrupt_checksum":
            return self._corrupt_checksums()
        else:  # null_injection
            return self._inject_null_bytes()

    # JPEG-specific mutation methods
    def _is_valid_jpeg(self) -> bool:
        """Check if data is valid JPEG."""
        return len(self.current_data) >= 3 and self.current_data.startswith(
            b"\xff\xd8\xff"
        )

    def _corrupt_jpeg_header(self) -> bytes:
        """Corrupt JPEG header structure."""
        if not self._is_valid_jpeg():
            return self.current_data

        result = bytearray(self.current_data)

        if len(result) > 4:
            result[2] = self.random.randint(0, 255)
            if self.random.random() < 0.5:
                result[3] = self.random.randint(0, 255)

        return bytes(result)

    def _mutate_jpeg_quantization(self) -> bytes:
        """Mutate JPEG quantization tables."""
        if not self._is_valid_jpeg():
            return self.current_data

        result = bytearray(self.current_data)

        # Look for quantization table markers (FF DB)
        for i in range(len(result) - 1):
            if result[i] == 0xFF and result[i + 1] == 0xDB:
                # Found quantization table marker, mutate table data
                if i + 4 < len(result):
                    # Get table length
                    table_length = (result[i + 2] << 8) | result[i + 3]
                    if i + table_length <= len(result):
                        # Mutate some table values
                        table_start = i + 4  # Skip marker and length
                        table_end = min(i + table_length, len(result))

                        for j in range(table_start, table_end):
                            if self.random.random() < 0.3:
                                result[j] = self.random.randint(0, 255)
                        break

        return bytes(result)

    def _mutate_jpeg_huffman(self) -> bytes:
        """Mutate JPEG Huffman tables."""
        if not self._is_valid_jpeg():
            return self.current_data

        result = bytearray(self.current_data)

        # Look for Huffman table markers (FF C4)
        for i in range(len(result) - 1):
            if result[i] == 0xFF and result[i + 1] == 0xC4:
                # Found Huffman table marker
                if i + 4 < len(result):
                    table_length = (result[i + 2] << 8) | result[i + 3]
                    if i + table_length <= len(result):
                        # Mutate Huffman table data
                        table_start = i + 4
                        table_end = min(i + table_length, len(result))

                        for j in range(table_start, table_end):
                            if self.random.random() < 0.2:
                                result[j] ^= 1 << self.random.randint(0, 7)
                        break

        return bytes(result)

    def _mutate_jpeg_dimensions(self) -> bytes:
        """Mutate JPEG image dimensions."""
        if not self._is_valid_jpeg():
            return self.current_data

        result = bytearray(self.current_data)

        # Look for SOF0 marker (FF C0) or similar start of frame markers
        sof_markers = [
            0xC0,
            0xC1,
            0xC2,
            0xC3,
            0xC5,
            0xC6,
            0xC7,
            0xC9,
            0xCA,
            0xCB,
            0xCD,
            0xCE,
            0xCF,
        ]

        for i in range(len(result) - 1):
            if result[i] == 0xFF and result[i + 1] in sof_markers:
                # Found SOF marker, dimensions are at offset +5 (height) and +7 (width)
                if i + 8 < len(result):
                    # Mutate height (2 bytes at offset +5)
                    height_mutation = self.random.choice(
                        [
                            0,  # Zero height
                            65535,  # Max height
                            self.random.randint(1, 10000),  # Random height
                            ((result[i + 5] << 8) | result[i + 6]) * 2,  # Double height
                            ((result[i + 5] << 8) | result[i + 6]) // 2,  # Half height
                        ]
                    )

                    result[i + 5] = (height_mutation >> 8) & 0xFF
                    result[i + 6] = height_mutation & 0xFF

                    # Mutate width (2 bytes at offset +7)
                    width_mutation = self.random.choice(
                        [
                            0,  # Zero width
                            65535,  # Max width
                            self.random.randint(1, 10000),  # Random width
                            ((result[i + 7] << 8) | result[i + 8]) * 2,  # Double width
                            ((result[i + 7] << 8) | result[i + 8]) // 2,  # Half width
                        ]
                    )

                    result[i + 7] = (width_mutation >> 8) & 0xFF
                    result[i + 8] = width_mutation & 0xFF
                break

        return bytes(result)

    def _inject_jpeg_comment(self) -> bytes:
        """Inject or corrupt JPEG comments."""
        if not self._is_valid_jpeg():
            return self.current_data

        result = bytearray(self.current_data)

        # Look for comment marker (FF FE) or create one
        comment_markers = []
        for i in range(len(result) - 1):
            if result[i] == 0xFF and result[i + 1] == 0xFE:
                comment_markers.append(i)

        if comment_markers:
            # Mutate existing comment
            marker_pos = self.random.choice(comment_markers)
            if marker_pos + 4 < len(result):
                comment_length = (result[marker_pos + 2] << 8) | result[marker_pos + 3]
                if marker_pos + comment_length <= len(result):
                    # Inject malicious content into comment
                    comment_start = marker_pos + 4
                    comment_end = min(marker_pos + comment_length, len(result))

                    malicious_content = self.random.choice(
                        [
                            b"\x00" * 50,  # Null bytes
                            b"A" * 100,  # Buffer overflow pattern
                            b"%n%n%n%n",  # Format string
                            b"../../../etc/passwd\0",  # Path traversal
                        ]
                    )

                    content_len = min(
                        len(malicious_content), comment_end - comment_start
                    )
                    result[comment_start : comment_start + content_len] = (
                        malicious_content[:content_len]
                    )
        else:
            # Insert new comment marker
            insert_pos = self.random.randint(2, min(100, len(result)))
            comment_data = b"\xff\xfe\x00\x20" + b"A" * 28  # Simple comment
            result[insert_pos:insert_pos] = comment_data

        return bytes(result)

    def _corrupt_jpeg_markers(self) -> bytes:
        """Corrupt JPEG segment markers."""
        if not self._is_valid_jpeg():
            return self.current_data

        result = bytearray(self.current_data)

        # Find and corrupt random markers
        markers = []
        for i in range(len(result) - 1):
            if result[i] == 0xFF:
                markers.append(i)

        if markers:
            # Corrupt 20-50% of markers
            num_to_corrupt = max(1, len(markers) // self.random.randint(2, 5))
            markers_to_corrupt = self.random.sample(
                markers, min(num_to_corrupt, len(markers))
            )

            for marker_pos in markers_to_corrupt:
                if marker_pos + 1 < len(result):
                    # Corrupt the marker byte
                    result[marker_pos + 1] = self.random.randint(0, 255)

        return bytes(result)

    # ELF-specific mutation methods
    def _is_valid_elf(self) -> bool:
        """Check if data is valid ELF."""
        return len(self.current_data) >= 4 and self.current_data.startswith(b"\x7fELF")

    def _corrupt_elf_header(self) -> bytes:
        """Corrupt ELF header fields."""
        if not self._is_valid_elf():
            return self.current_data

        result = bytearray(self.current_data)

        # ELF header is 52 bytes for 32-bit, 64 bytes for 64-bit
        if len(result) >= 52:
            # Target critical header fields
            fields_to_corrupt = self.random.sample(
                [
                    4,  # EI_CLASS (32/64 bit)
                    5,  # EI_DATA (endianness)
                    6,  # EI_VERSION
                    7,  # EI_OSABI
                    8,  # EI_ABIVERSION
                    16,  # e_type (executable type)
                    18,  # e_machine (architecture)
                    20,  # e_version
                    24,  # e_entry (entry point) - 4 bytes
                    28,  # e_phoff (program header offset) - 4 bytes
                    32,  # e_shoff (section header offset) - 4 bytes
                ],
                min(3, 8),
            )  # Corrupt up to 3 fields

            for field_offset in fields_to_corrupt:
                if field_offset < len(result):
                    if field_offset in [24, 28, 32]:  # Multi-byte fields
                        # Corrupt all bytes of the field
                        for i in range(4):
                            if field_offset + i < len(result):
                                result[field_offset + i] = self.random.randint(0, 255)
                    else:
                        result[field_offset] = self.random.randint(0, 255)

        return bytes(result)

    def _mutate_elf_sections(self) -> bytes:
        """Mutate ELF section headers."""
        if not self._is_valid_elf():
            return self.current_data

        result = bytearray(self.current_data)

        # Section header table offset is at bytes 32-35 (32-bit) or 40-47 (64-bit)
        if len(result) >= 40:
            # Determine if 32-bit or 64-bit ELF
            is_64bit = result[4] == 2

            if is_64bit and len(result) >= 64:
                shoff = (
                    (result[40] << 24)
                    | (result[41] << 16)
                    | (result[42] << 8)
                    | result[43]
                )
                shoff |= (
                    (result[44] << 56)
                    | (result[45] << 48)
                    | (result[46] << 40)
                    | (result[47] << 32)
                )
                shent_size = 64  # 64-bit section header size
            else:
                shoff = (
                    (result[32] << 24)
                    | (result[33] << 16)
                    | (result[34] << 8)
                    | result[35]
                )
                shent_size = 40  # 32-bit section header size

            # Mutate some section headers if they exist
            if shoff > 0 and shoff + shent_size <= len(result):
                # Mutate first few section headers
                for i in range(min(3, (len(result) - shoff) // shent_size)):
                    section_start = shoff + (i * shent_size)
                    if section_start + shent_size <= len(result):
                        # Mutate section name offset, type, flags, etc.
                        for j in range(min(16, shent_size)):  # Mutate first 16 bytes
                            if self.random.random() < 0.3:
                                result[section_start + j] = self.random.randint(0, 255)

        return bytes(result)

    def _mutate_elf_segments(self) -> bytes:
        """Mutate ELF program headers (segments)."""
        if not self._is_valid_elf():
            return self.current_data

        result = bytearray(self.current_data)

        # Program header table offset is at bytes 28-31 (32-bit) or 32-39 (64-bit)
        if len(result) >= 32:
            is_64bit = result[4] == 2

            if is_64bit and len(result) >= 64:
                phoff = (
                    (result[32] << 24)
                    | (result[33] << 16)
                    | (result[34] << 8)
                    | result[35]
                )
                phoff |= (
                    (result[36] << 56)
                    | (result[37] << 48)
                    | (result[38] << 40)
                    | (result[39] << 32)
                )
                phent_size = 56  # 64-bit program header size
            else:
                phoff = (
                    (result[28] << 24)
                    | (result[29] << 16)
                    | (result[30] << 8)
                    | result[31]
                )
                phent_size = 32  # 32-bit program header size

            # Mutate program headers if they exist
            if phoff > 0 and phoff + phent_size <= len(result):
                # Mutate first few program headers
                for i in range(min(2, (len(result) - phoff) // phent_size)):
                    segment_start = phoff + (i * phent_size)
                    if segment_start + phent_size <= len(result):
                        # Mutate segment type, flags, offset, etc.
                        for j in range(min(20, phent_size)):  # Mutate first 20 bytes
                            if self.random.random() < 0.3:
                                result[segment_start + j] = self.random.randint(0, 255)

        return bytes(result)

    def _corrupt_elf_symbols(self) -> bytes:
        """Corrupt ELF symbol table."""
        if not self._is_valid_elf():
            return self.current_data

        result = bytearray(self.current_data)

        # This is complex - for now just corrupt random sections that might contain symbols
        # Look for .symtab or .strtab sections
        if len(result) > 100:
            # Search for section names in string table
            for i in range(100, min(1000, len(result))):
                if result[i : i + 7] == b".symtab" or result[i : i + 7] == b".strtab":
                    # Found symbol section, corrupt surrounding area
                    start = max(0, i - 50)
                    end = min(len(result), i + 100)
                    for j in range(start, end):
                        if self.random.random() < 0.1:
                            result[j] = self.random.randint(0, 255)
                    break

        return bytes(result)

    def _mutate_elf_relocations(self) -> bytes:
        """Mutate ELF relocation entries."""
        if not self._is_valid_elf():
            return self.current_data

        result = bytearray(self.current_data)

        # Look for relocation sections (.rel.text, .rel.data, etc.)
        if len(result) > 100:
            for i in range(100, min(1000, len(result))):
                if (
                    result[i : i + 8] == b".rel.text"
                    or result[i : i + 8] == b".rel.data"
                    or result[i : i + 9] == b".rela.text"
                    or result[i : i + 9] == b".rela.data"
                ):
                    # Found relocation section, corrupt it
                    start = max(0, i - 20)
                    end = min(len(result), i + 200)
                    for j in range(start, end):
                        if self.random.random() < 0.2:
                            result[j] = self.random.randint(0, 255)
                    break

        return bytes(result)

    def _mutate_elf_entry_point(self) -> bytes:
        """Mutate ELF entry point."""
        if not self._is_valid_elf():
            return self.current_data

        result = bytearray(self.current_data)

        # Entry point is at bytes 24-27 (32-bit) or 24-31 (64-bit)
        if len(result) >= 28:
            is_64bit = result[4] == 2

            if is_64bit and len(result) >= 32:
                # 64-bit entry point
                for i in range(24, 32):
                    result[i] = self.random.randint(0, 255)
            else:
                # 32-bit entry point
                for i in range(24, 28):
                    result[i] = self.random.randint(0, 255)

        return bytes(result)

    # PDF-specific mutation methods
    def _is_valid_pdf(self) -> bool:
        """Check if data is valid PDF."""
        return len(self.current_data) >= 4 and self.current_data.startswith(b"%PDF")

    def _corrupt_pdf_header(self) -> bytes:
        """Corrupt PDF header."""
        if not self._is_valid_pdf():
            return self.current_data

        result = bytearray(self.current_data)

        # Corrupt PDF version
        if len(result) >= 8:
            # PDF header is like "%PDF-1.4"
            for i in range(5, 8):  # Corrupt version number
                result[i] = self.random.choice(
                    [
                        ord("0"),
                        ord("1"),
                        ord("2"),
                        ord("3"),
                        ord("4"),
                        ord("5"),
                        ord("6"),
                        ord("7"),
                        ord("8"),
                        ord("9"),
                        ord("."),
                    ]
                )

        return bytes(result)

    def _mutate_pdf_xref(self) -> bytes:
        """Mutate PDF cross-reference table."""
        if not self._is_valid_pdf():
            return self.current_data

        result = bytearray(self.current_data)

        # Look for "xref" keyword
        pdf_text = result.decode("utf-8", errors="ignore")
        xref_pos = pdf_text.find("xref")

        if xref_pos != -1:
            # Found xref table, corrupt it
            start_pos = xref_pos
            end_pos = pdf_text.find("trailer", start_pos)
            if end_pos == -1:
                end_pos = len(result)

            # Corrupt portion of xref table
            for i in range(start_pos, min(start_pos + 200, end_pos)):
                if self.random.random() < 0.3:
                    result[i] = self.random.randint(32, 126)  # Printable ASCII

        return bytes(result)

    def _mutate_pdf_objects(self) -> bytes:
        """Mutate PDF objects."""
        if not self._is_valid_pdf():
            return self.current_data

        result = bytearray(self.current_data)

        # Look for object patterns (like "1 0 obj")
        pdf_text = result.decode("utf-8", errors="ignore")

        import re

        obj_pattern = r"(\d+)\s+(\d+)\s+obj"
        matches = list(re.finditer(obj_pattern, pdf_text))

        if matches:
            # Mutate random objects
            num_to_mutate = min(3, len(matches))
            objects_to_mutate = self.random.sample(matches, num_to_mutate)

            for match in objects_to_mutate:
                start = match.start()
                # Find end of object (look for "endobj")
                endobj_pos = pdf_text.find("endobj", start)
                if endobj_pos != -1:
                    end = endobj_pos + 6  # Include "endobj"
                    # Corrupt this object
                    for i in range(start, min(end, len(result))):
                        if self.random.random() < 0.2:
                            result[i] = self.random.randint(32, 126)

        return bytes(result)

    def _corrupt_pdf_streams(self) -> bytes:
        """Corrupt PDF stream data."""
        if not self._is_valid_pdf():
            return self.current_data

        result = bytearray(self.current_data)

        # Look for "stream" and "endstream" keywords
        pdf_text = result.decode("utf-8", errors="ignore")
        stream_pos = pdf_text.find("stream")

        while stream_pos != -1:
            # Find end of this stream
            endstream_pos = pdf_text.find("endstream", stream_pos)
            if endstream_pos != -1:
                # Stream data is between "stream\n" and "\nendstream"
                stream_start = stream_pos + len("stream")
                # Skip newline after "stream"
                while stream_start < len(result) and result[stream_start] in [
                    10,
                    13,
                ]:  # \n or \r
                    stream_start += 1

                stream_end = endstream_pos
                # Find newline before "endstream"
                while stream_end > stream_start and result[stream_end - 1] not in [
                    10,
                    13,
                ]:
                    stream_end -= 1

                # Corrupt stream data
                if stream_end > stream_start:
                    for i in range(stream_start, stream_end):
                        if self.random.random() < 0.3:
                            result[i] = self.random.randint(0, 255)

            # Look for next stream
            stream_pos = pdf_text.find(
                "stream", endstream_pos if endstream_pos != -1 else stream_pos + 1
            )

        return bytes(result)

    def _mutate_pdf_filters(self) -> bytes:
        """Mutate PDF filter specifications."""
        if not self._is_valid_pdf():
            return self.current_data

        result = bytearray(self.current_data)

        # Look for filter keywords
        filters = [
            b"/FlateDecode",
            b"/ASCIIHexDecode",
            b"/ASCII85Decode",
            b"/LZWDecode",
            b"/RunLengthDecode",
            b"/CCITTFaxDecode",
            b"/DCTDecode",
            b"/JPXDecode",
        ]

        for filter_bytes in filters:
            pos = result.find(filter_bytes)
            if pos != -1:
                # Replace filter with something else
                replacement = self.random.choice(
                    [
                        b"/InvalidFilter",
                        b"/FlateDecode",  # Force compression
                        b"/ASCIIHexDecode",
                        b"",
                    ]
                )

                # Replace in result
                result[pos : pos + len(filter_bytes)] = replacement
                break  # Only mutate one filter

        return bytes(result)

    def _mutate_pdf_trailer(self) -> bytes:
        """Mutate PDF trailer."""
        if not self._is_valid_pdf():
            return self.current_data

        result = bytearray(self.current_data)

        # Look for "trailer" keyword
        pdf_text = result.decode("utf-8", errors="ignore")
        trailer_pos = pdf_text.rfind("trailer")  # Use last trailer

        if trailer_pos != -1:
            # Mutate trailer section
            start = trailer_pos
            # Find startxref
            startxref_pos = pdf_text.find("startxref", start)
            if startxref_pos == -1:
                startxref_pos = len(result)

            # Corrupt trailer
            for i in range(start, min(start + 200, startxref_pos)):
                if self.random.random() < 0.2:
                    result[i] = self.random.randint(32, 126)

        return bytes(result)

    # Generic binary mutation helper methods
    def _repeat_patterns(self) -> bytes:
        """Repeat patterns in the binary."""
        if not self.current_data or len(self.current_data) < 4:
            return self.current_data

        result = bytearray(self.current_data)

        # Find a pattern to repeat
        pattern_length = self.random.randint(2, 8)
        pattern_start = self.random.randint(0, len(result) - pattern_length)
        pattern = result[pattern_start : pattern_start + pattern_length]

        # Repeat the pattern
        repeat_count = self.random.randint(2, 10)
        insert_pos = self.random.randint(0, len(result))

        for _ in range(repeat_count):
            result[insert_pos:insert_pos] = pattern
            insert_pos += pattern_length

        return bytes(result)

    def _swap_chunks(self) -> bytes:
        """Swap chunks of the binary."""
        if not self.current_data or len(self.current_data) < 8:
            return self.current_data

        result = bytearray(self.current_data)
        chunk_size = self.random.randint(2, min(16, len(result) // 4))

        # Find two chunks to swap
        chunk1_start = self.random.randint(0, len(result) - chunk_size)
        chunk2_start = self.random.randint(0, len(result) - chunk_size)

        # Ensure chunks don't overlap
        if abs(chunk1_start - chunk2_start) < chunk_size:
            return self.current_data

        # Swap chunks
        chunk1 = result[chunk1_start : chunk1_start + chunk_size]
        chunk2 = result[chunk2_start : chunk2_start + chunk_size]

        result[chunk1_start : chunk1_start + chunk_size] = chunk2
        result[chunk2_start : chunk2_start + chunk_size] = chunk1

        return bytes(result)

    def _corrupt_checksums(self) -> bytes:
        """Attempt to corrupt checksum-like values."""
        if not self.current_data or len(self.current_data) < 4:
            return self.current_data

        result = bytearray(self.current_data)

        # Look for patterns that might be checksums
        # (simple heuristic: consecutive zeros or repeated patterns at the end)
        if len(result) >= 8:
            # Check last 8 bytes for checksum-like patterns
            tail = result[-8:]

            # If all zeros, corrupt them
            if all(b == 0 for b in tail):
                for i in range(-8, 0):
                    result[i] = self.random.randint(0, 255)
            # If all same byte, corrupt them
            elif len(set(tail)) == 1:
                for i in range(-8, 0):
                    result[i] = self.random.randint(0, 255)

        return bytes(result)

    def _inject_null_bytes(self) -> bytes:
        """Inject null bytes into the binary."""
        if not self.current_data:
            return self.current_data

        result = bytearray(self.current_data)

        # Inject null bytes at random positions
        num_nulls = self.random.randint(1, 10)
        for _ in range(num_nulls):
            insert_pos = self.random.randint(0, len(result))
            result.insert(insert_pos, 0)

        return bytes(result)

    def reset(self) -> None:
        """Reset the mutator to its original state."""
        self.current_data = self.original_data
        self.mutation_count = 0

    def _validate_structure(self, data: bytes) -> bool:
        """Basic validation - check if data is not empty."""
        return len(data) > 0

    def generate_mutation_description(self) -> str:
        """Generate a description of the last mutation."""
        size = len(self.current_data)
        return f"Binary mutation #{self.mutation_count} ({self.input_format.value}, {size} bytes)"

    def _increment_mutation_count(self) -> None:
        """Increment the mutation counter."""
        super()._increment_mutation_count()


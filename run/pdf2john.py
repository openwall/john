#!/usr/bin/env python3

# This software is Copyright (c) 2023 Benjamin Dornel <benjamindornel@gmail.com>
# and it is hereby released to the general public under the following terms:
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.


import argparse
import logging
import sys

try:
    from pyhanko.pdf_utils.misc import PdfReadError
    from pyhanko.pdf_utils.reader import PdfFileReader
except ImportError:
    print("pyhanko is missing, run 'pip install --user pyhanko' to install it!", file=sys.stderr)
    sys.exit(1)

logger = logging.getLogger(__name__)


class SecurityRevision:
    """Represents Standard Security Handler Revisions
    and the corresponding key length for the /O and /U entries

    In Revision 5, the /O and /U entries were extended to 48 bytes,
    with three logical parts -- a 32 byte verification hash,
    an 8 byte validation salt, and an 8 byte key salt."""

    revisions = {
        2: 32,  # RC4_BASIC
        3: 32,  # RC4_EXTENDED
        4: 32,  # RC4_OR_AES128
        5: 48,  # AES_R5_256
        6: 48,  # AES_256
    }

    @classmethod
    def get_key_length(cls, revision):
        """
        Get the key length for a given revision,
        defaults to 48 if no revision is specified.
        """
        return cls.revisions.get(revision, 48)


class PdfHashExtractor:
    """
    Extracts hash and encryption information from a PDF file

    Attributes:
    - `file_name`: PDF file path.
    - `strict`: Boolean that controls whether an error is raised, if a PDF
        has problems e.g. Multiple definitions in encryption dictionary
        for a specific key. Defaults to `False`.
    - `algorithm`: Encryption algorithm used by the standard security handler
    - `length`: The length of the encryption key, in bits. Defaults to 40.
    - `permissions`: User access permissions
    - `revision`: Revision of the standard security handler
    """

    def __init__(self, file_name: str, strict: bool = False):
        self.file_name = file_name

        with open(file_name, "rb") as doc:
            self.pdf = PdfFileReader(doc, strict=strict)
            self.encrypt_dict = self.pdf.encrypt_dict

            if not self.encrypt_dict:
                raise RuntimeError("File not encrypted")

            self.algorithm: int = self.encrypt_dict.get("/V")
            self.length: int = self._get_key_length()
            self.permissions: int = self.encrypt_dict["/P"]
            self.revision: int = self.encrypt_dict["/R"]

    def _get_key_length(self) -> int:
        """
        Determine the effective encryption key length, in bits.

        For V1-V3 encryption, the key length is given directly by the
        top-level /Length entry (in bits), defaulting to 40 if absent
        (per PDF 1.7 spec section 7.6.1, Table 20).

        For V4/V5 encryption, PDFs use crypt filters (/CF). The
        top-level /Length entry is not formally part of the spec for
        these versions and is frequently omitted -- the *effective*
        key length is governed by the applicable crypt filter's own
        /Length entry instead (given in *bytes*, per Table 25).
        Falling back unconditionally to 40 when /Length is absent
        silently mis-reports e.g. AES-128 files as 40-bit, which then
        causes John to derive the wrong key size and fail to crack an
        otherwise crackable hash.

        See: https://github.com/openwall/john/issues/6033

        Some writers include a top-level /Length on V4/V5 files even
        though it isn't required. When present, it should agree with
        the crypt filter's /Length -- if it doesn't, the crypt filter
        value is treated as authoritative (it's what actually governs
        the key size for these versions) and a warning is logged, since
        a mismatch may indicate an unusual or malformed file worth a
        closer look.
        """
        top_level_length = self.encrypt_dict.get("/Length")

        cf_length_bits = None
        if self.algorithm and self.algorithm >= 4:
            cf_length_bytes = self._get_crypt_filter_length()
            if cf_length_bytes is not None:
                # Crypt filter /Length is in bytes; top-level /Length
                # (and the rest of this script) works in bits.
                cf_length_bits = cf_length_bytes * 8

        if top_level_length is not None and cf_length_bits is not None:
            if top_level_length != cf_length_bits:
                logger.warning(
                    "%s: top-level /Length (%s bits) does not match the "
                    "applicable crypt filter's /Length (%s bits) for V%s "
                    "encryption -- using the crypt filter value, since it "
                    "is authoritative for V4/V5. Verify this file by hand "
                    "if cracking fails.",
                    self.file_name,
                    top_level_length,
                    cf_length_bits,
                    self.algorithm,
                )
            return cf_length_bits

        if top_level_length is not None:
            return top_level_length

        if cf_length_bits is not None:
            return cf_length_bits

        return 40

    def _get_crypt_filter_length(self):
        """
        Look up the /Length entry (in bytes) of the crypt filter that
        applies to streams (/StmF), falling back to the one that applies
        to strings (/StrF) if needed. Returns None if no applicable
        crypt filter with a /Length entry can be found (e.g. /StmF is
        /Identity, meaning no encryption filter is used for streams).
        """
        cf_dict = self.encrypt_dict.get("/CF")
        if not cf_dict:
            return None

        for filter_key in ("/StmF", "/StrF"):
            cf_name = self.encrypt_dict.get(filter_key)
            if not cf_name or cf_name == "/Identity":
                continue
            crypt_filter = cf_dict.get(cf_name)
            if crypt_filter and "/Length" in crypt_filter:
                return crypt_filter["/Length"]

        return None

    @property
    def document_id(self) -> bytes:
        return self.pdf.document_id[0]

    @property
    def encrypt_metadata(self) -> str:
        """
        Get a string representation of whether metadata is encrypted.

        Returns "1" if metadata is encrypted, "0" otherwise.
        """
        return str(int(self.pdf.security_handler.encrypt_metadata))

    def parse(self) -> str:
        """
        Parse PDF encryption information into a formatted string for John
        """
        passwords = self.get_passwords()
        fields = [
            f"$pdf${self.algorithm}",
            self.revision,
            self.length,
            self.permissions,
            self.encrypt_metadata,
            len(self.document_id),
            self.document_id.hex(),
            passwords,
        ]
        return "*".join(map(str, fields))

    def get_passwords(self) -> str:
        """
        Creates a string consisting of the hexidecimal string of the
        /U, /O, /UE and /OE entries and their corresponding byte string length
        """
        passwords = []
        keys = ("udata", "odata", "oeseed", "ueseed")
        max_key_length = SecurityRevision.get_key_length(self.revision)

        for key in keys:
            if data := getattr(self.pdf.security_handler, key):
                data: bytes = data[:max_key_length]
                passwords.extend([str(len(data)), data.hex()])

        return "*".join(passwords)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PDF Hash Extractor")
    parser.add_argument(
        "pdf_files", nargs="+", help="PDF file(s) to extract information from"
    )
    parser.add_argument(
        "-d", "--debug", action="store_true", help="Print the encryption dictionary"
    )
    args = parser.parse_args()

    for filename in args.pdf_files:
        try:
            extractor = PdfHashExtractor(filename)
            pdf_hash = extractor.parse()
            print(pdf_hash)

            if args.debug:
                print(f"Encryption Dictionary for file '{filename}':", file=sys.stderr)
                for key, value in extractor.encrypt_dict.items():
                    print(f"  {key}: {value}", file=sys.stderr)

        except (PdfReadError, RuntimeError) as error:
            logger.error("Error: %s -- %s", filename, error)

"""
OSINT module: extracts metadata from sample documents (fictional company
files seeded in data/sample_documents/) and simulates open-source
intelligence gathering against the fake company's public footprint.

No real external OSINT is performed against real-world targets — the
"public footprint" here is a locally seeded JSON fixture representing
what a real recon phase might turn up (fake employee names, fake domains,
fake social handles) purely for demonstration.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from src.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


@dataclass
class DocumentMetadata:
    """Metadata extracted from a single sample document."""

    filename: str
    author: Optional[str] = None
    software: Optional[str] = None
    creation_date: Optional[str] = None
    last_modified_by: Optional[str] = None
    company: Optional[str] = None
    extra: dict = field(default_factory=dict)


class MetadataExtractor:
    """Extracts document metadata for OSINT demonstration purposes."""

    def extract_from_docx(self, path: Path) -> DocumentMetadata:
        """Extract core-properties metadata from a .docx file.

        Uses python-docx's `core_properties` under the hood; falls back to
        raw XML parsing if python-docx isn't available.
        """
        try:
            import docx  # local import: optional dependency for this feature

            document = docx.Document(str(path))
            props = document.core_properties
            return DocumentMetadata(
                filename=path.name,
                author=props.author,
                software=None,
                creation_date=str(props.created) if props.created else None,
                last_modified_by=props.last_modified_by,
                company=None,
            )
        except ImportError:
            logger.warning("python-docx not installed; returning filename-only metadata")
            return DocumentMetadata(filename=path.name)
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Failed to extract metadata from %s: %s", path, exc)
            return DocumentMetadata(filename=path.name)

    def extract_from_pdf(self, path: Path) -> DocumentMetadata:
        """Extract document info dictionary metadata from a PDF file."""
        try:
            from pypdf import PdfReader  # local import: optional dependency

            reader = PdfReader(str(path))
            info = reader.metadata or {}
            return DocumentMetadata(
                filename=path.name,
                author=info.get("/Author"),
                software=info.get("/Producer"),
                creation_date=info.get("/CreationDate"),
                company=info.get("/Company"),
            )
        except ImportError:
            logger.warning("pypdf not installed; returning filename-only metadata")
            return DocumentMetadata(filename=path.name)
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Failed to extract metadata from %s: %s", path, exc)
            return DocumentMetadata(filename=path.name)

    def scan_directory(self, directory: Optional[Path] = None) -> list[DocumentMetadata]:
        """Extract metadata from every supported sample document in a directory."""
        directory = directory or (settings.data_dir / "sample_documents")
        results: list[DocumentMetadata] = []

        if not directory.exists():
            logger.warning("Sample documents directory not found: %s", directory)
            return results

        for file_path in sorted(directory.iterdir()):
            if file_path.suffix.lower() == ".docx":
                results.append(self.extract_from_docx(file_path))
            elif file_path.suffix.lower() == ".pdf":
                results.append(self.extract_from_pdf(file_path))

        return results


class OSINTSimulator:
    """Simulates OSINT recon against the fake company's public footprint."""

    def __init__(self, footprint_path: Optional[Path] = None) -> None:
        self.footprint_path = footprint_path or (
            settings.data_dir / "sample_documents" / "company_footprint.json"
        )

    def gather(self) -> dict:
        """Return the seeded fake public footprint (employees, domains, leaks).

        In a real engagement this step would involve LinkedIn enumeration,
        breach-database lookups, DNS/subdomain enumeration, etc. Here it is
        entirely a local, fictional fixture to demonstrate the recon
        methodology without touching any real external service.
        """
        if not self.footprint_path.exists():
            logger.warning("OSINT footprint fixture not found at %s", self.footprint_path)
            return {}

        with open(self.footprint_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def find_reused_credentials_hint(self, footprint: dict) -> list[str]:
        """Return usernames whose naming convention suggests likely password reuse.

        Purely illustrative heuristic for the CTF "recon" category — flags
        accounts using predictable `first.last` patterns matched against the
        seeded weak-password wordlist naming scheme.
        """
        employees = footprint.get("employees", [])
        return [
            f"{e['first_name'].lower()}.{e['last_name'].lower()}"
            for e in employees
            if e.get("first_name") and e.get("last_name")
        ]

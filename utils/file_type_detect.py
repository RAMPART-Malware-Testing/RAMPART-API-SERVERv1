"""Content-derived file classification.

The filename a client sends with an upload is attacker-controlled, so it can
never be the source of truth for what a file actually is. This module reads
the first bytes of the file on disk and maps them to a stable category, and
provides a fallback that reads VirusTotal's own verdict for files magic
bytes alone cannot classify (scripts, documents).

Every classifier returns a `Detection` whose `source` says where the answer
came from, so callers can record how much the label is worth.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

SNIFF_BYTES = 4096
# A zip's central directory lives at the end of the file. 64KB of tail covers
# every real APK and OOXML package while staying cheap to read.
ZIP_TAIL_BYTES = 64 * 1024

UNKNOWN = "unknown"


@dataclass(frozen=True)
class Detection:
    """A file category plus the evidence that produced it."""

    category: str
    source: str
    label: str = ""
    extensions: tuple[str, ...] = ()
    # Set when the bytes are readable text but the uploaded suffix claims a
    # binary format - a `.exe` that is really a shell script. The category
    # stays `unknown` because the content alone cannot name the language, but
    # the contradiction itself is worth surfacing.
    contradicted_binary_claim: bool = False

    @property
    def extensions_text(self) -> str:
        return ", ".join(self.extensions)


# Category key -> what the dashboard shows the user. Extensions are what the
# category is *expected* to look like, used only to explain the grouping.
CATEGORIES: dict[str, str] = {
    "windows-exe": "Windows Executable",
    "windows-dll": "Windows DLL",
    "windows-installer": "Windows Installer",
    "android-apk": "Android Package",
    "linux-elf": "Linux ELF",
    "macos-macho": "macOS Mach-O",
    "script": "Script",
    "document": "Document",
    "archive": "Archive",
    "other-binary": "Other Binary",
    UNKNOWN: "ไม่ระบุ",
}

CATEGORY_EXTENSIONS: dict[str, tuple[str, ...]] = {
    # `.sys` and `.com` are Windows PE images too - a driver and a COM object
    # are distinguished by their entry point, not by their file format.
    "windows-exe": ("exe", "scr", "com", "cpl", "sys"),
    "windows-dll": ("dll", "ocx"),
    "windows-installer": ("msi", "msp"),
    "android-apk": ("apk", "xapk", "apks", "aab", "ipa"),
    "linux-elf": ("elf", "so"),
    "macos-macho": ("macho", "dylib"),
    "script": (
        "py", "ps1", "psm1", "sh", "bash", "zsh", "js", "jsx", "vbs",
        "bat", "cmd", "pl", "rb", "php", "wsf", "hta",
    ),
    "document": ("pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "rtf", "pub"),
    "archive": ("zip", "jar", "war", "rar", "7z", "gz", "tgz", "bz2", "xz", "tar", "cab", "iso"),
    # Images, audio and video have no analysis tooling of their own, but they
    # need an owner so that a binary renamed to `.png` is still recognised as
    # the contradiction it is.
    "other-binary": (
        "bin", "dat", "img", "db", "sqlite",
        "jpg", "jpeg", "png", "gif", "bmp", "webp", "ico", "tiff", "svg",
        "mp3", "mp4", "avi", "mkv", "wav", "mov", "flac", "ogg",
        "ttf", "otf", "woff", "woff2", "eot",
    ),
}

# Every extension the taxonomy knows about, and the category it implies. Used
# to decide whether an unrecognised suffix is a genuine contradiction or just
# a name the taxonomy has never seen.
_EXTENSION_OWNER: dict[str, str] = {
    extension: category
    for category, extensions in CATEGORY_EXTENSIONS.items()
    for extension in extensions
}

_PE_SIGNATURE = b"MZ"
_MS_CFB_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_ZIP_SIGNATURE = b"PK\x03\x04"
_ZIP_EMPTY_SIGNATURE = b"PK\x05\x06"
_ZIP_SPANNED_SIGNATURE = b"PK\x07\x08"
_RAR_SIGNATURE = b"Rar!\x1a\x07"
_7Z_SIGNATURE = b"7z\xbc\xaf\x27\x1c"
_GZIP_SIGNATURE = b"\x1f\x8b"
_BZIP2_SIGNATURE = b"BZh"
_XZ_SIGNATURE = b"\xfd7zXZ\x00"
_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce": "macos-macho",
    b"\xfe\xed\xfa\xcf": "macos-macho",
    b"\xce\xfa\xed\xfe": "macos-macho",
    b"\xcf\xfa\xed\xfe": "macos-macho",
    b"\xca\xfe\xba\xbe": "macos-macho",
}

_SHEBANG = b"#!"

_VT_TAG_TO_CATEGORY = {
    "peexe": "windows-exe",
    "pedll": "windows-dll",
    "msi": "windows-installer",
    "apk": "android-apk",
    "elf": "linux-elf",
    "macho": "macos-macho",
    "office": "document",
    "document": "document",
    "msoffice": "document",
    "vba": "script",
    "ps1": "script",
    "javascript": "script",
    "js": "script",
    "python": "script",
    "shell": "script",
    "bat": "script",
    "ruby": "script",
    "perl": "script",
    "php": "script",
    "zip": "archive",
    "gzip": "archive",
    "rar": "archive",
    "7z": "archive",
    "cab": "archive",
    "tar": "archive",
}

_VT_DESCRIPTION_TO_CATEGORY = (
    (r"\bapk\b|android", "android-apk"),
    (r"\bmach-?o\b|mac-?os|osx|darwin", "macos-macho"),
    (r"\belf\b|linux", "linux-elf"),
    (r"installer|\bmsi\b", "windows-installer"),
    (r"\bdll\b|dynamic[- ]link", "windows-dll"),
    (r"\bexe\b|executable|win32", "windows-exe"),
    (r"javascript|typescript", "script"),
    (r"powershell|shell script|bash|python|perl|php|vbscript|batch|vba", "script"),
    (r"\bjar\b|\bjava\b|byte-?code", "archive"),
    (r"excel|word|powerpoint|office|spreadsheet|document|pdf|rtf", "document"),
    (r"\bzip\b|archive|\bgzip\b|\brar\b|\b7z\b|tar", "archive"),
)

# Extensions that are plausibly text and worth a content sniff even without a
# shebang. Everything else needs a real magic header to be classified.
_TEXTUAL_EXTENSIONS = frozenset(CATEGORY_EXTENSIONS["document"]) | frozenset(CATEGORY_EXTENSIONS["script"])


def _clean_extension(extension: str | None) -> str:
    if not extension:
        return ""
    cleaned = extension.strip().lower().lstrip(".")
    return cleaned if re.fullmatch(r"[a-z0-9]{1,10}", cleaned) else ""


def _zip_category(head: bytes) -> str:
    """Tell a real APK or OOXML document apart from any other zip.

    Entry names are stored uncompressed in both the local header and the
    central directory, so a substring search over the sniff window finds the
    marker even when the entry that carries it is not the first one - which is
    the common case for APKs, whose first entries are usually resources.
    """
    lowered = head.lower()
    if b"androidmanifest.xml" in lowered or b"classes.dex" in lowered:
        return "android-apk"
    if b"[content_types].xml" in lowered:
        return "document"
    return "archive"


def _looks_like_zip(head: bytes) -> bool:
    return head.startswith(_ZIP_SIGNATURE) or head.startswith(_ZIP_EMPTY_SIGNATURE) or head.startswith(_ZIP_SPANNED_SIGNATURE)


def _pe_subsystem(head: bytes) -> str | None:
    """Distinguish a PE executable from a PE DLL using the characteristics word.

    IMAGE_FILE_DLL is 0x2000 in the COFF characteristics field, which sits at a
    fixed offset from the `PE\\0\\0` signature.
    """
    pe_offset = int.from_bytes(head[0x3c:0x40], "little") if len(head) >= 0x40 else 0
    if not 0 < pe_offset < 0x1000 or pe_offset + 6 > len(head):
        return None
    if head[pe_offset: pe_offset + 4] != b"PE\x00\x00":
        return None
    characteristics = int.from_bytes(head[pe_offset + 22: pe_offset + 24], "little") if pe_offset + 24 <= len(head) else 0
    return "windows-dll" if characteristics & 0x2000 else "windows-exe"


def _looks_like_text(head: bytes) -> bool:
    if not head:
        return False
    printable = sum(1 for byte in head if 9 <= byte <= 13 or 32 <= byte <= 126)
    return printable / len(head) > 0.95


def _script_from_text(head: bytes, extension: str) -> str | None:
    if not head:
        return None
    if head.startswith(_SHEBANG):
        return "script"
    if extension in _TEXTUAL_EXTENSIONS:
        return "script"
    # Plain text with no shebang is only labelled a document, never a script:
    # a .txt full of shell commands and a Python module are the same bytes here,
    # and calling either one a script on this evidence alone would be a guess.
    if extension in CATEGORY_EXTENSIONS["document"] and _looks_like_text(head):
        return "document"
    return None


def _from_magic(head: bytes, extension: str) -> str | None:
    if head.startswith(b"\x7fELF"):
        return "linux-elf"
    for magic, category in _MACHO_MAGICS.items():
        if head.startswith(magic):
            return category
    if head.startswith(_MS_CFB_SIGNATURE):
        return "windows-installer" if extension in {"msi", "msp"} else "document"
    if head.startswith(_PE_SIGNATURE):
        return _pe_subsystem(head)
    if _looks_like_zip(head):
        return _zip_category(head)
    if head.startswith(_RAR_SIGNATURE) or head.startswith(_7Z_SIGNATURE):
        return "archive"
    if head.startswith(_GZIP_SIGNATURE) or head.startswith(_BZIP2_SIGNATURE) or head.startswith(_XZ_SIGNATURE):
        return "archive"
    if head.startswith(b"%PDF"):
        return "document"
    return _script_from_text(head, extension)


def detect_from_bytes(head: bytes, extension: str | None = None) -> Detection:
    """Classify from a leading byte window. `extension` only breaks ties."""
    clean_extension = _clean_extension(extension)
    category = _from_magic(head, clean_extension)
    if category is None:
        # Nothing matched. If the suffix claims a binary format but the bytes
        # are plain text, that is a contradiction worth recording even though
        # the category itself stays unknown.
        claimed = _EXTENSION_OWNER.get(clean_extension)
        contradicted = (
            claimed is not None
            and claimed not in _TEXTUAL_EXTENSIONS
            and _looks_like_text(head)
        )
        return Detection(UNKNOWN, "magic", CATEGORIES[UNKNOWN], (), contradicted)
    return Detection(category, "magic", CATEGORIES.get(category, category), CATEGORY_EXTENSIONS.get(category, ()))


def detect_from_file(path: str | Path, extension: str | None = None) -> Detection:
    """Classify a file on disk, falling back to its suffix only when magic fails."""
    file_path = Path(path)
    suffix = extension if extension is not None else file_path.suffix
    try:
        with file_path.open("rb") as handle:
            head = handle.read(SNIFF_BYTES)
    except OSError:
        return _from_extension(suffix)

    detection = detect_from_bytes(head, suffix)

    # A zip's own directory sits at the *end* of the file, so a large APK whose
    # AndroidManifest.xml is past the sniff window looks like a plain archive.
    # Re-read the tail before settling for that answer.
    if detection.category == "archive":
        refined = _refine_zip(file_path, detection)
        if refined is not None:
            return refined

    return detection


def _refine_zip(file_path: Path, detection: Detection) -> Detection | None:
    """Look at a zip's tail for the entries that identify an APK or a document."""
    try:
        size = file_path.stat().st_size
        with file_path.open("rb") as handle:
            handle.seek(max(0, size - ZIP_TAIL_BYTES))
            tail = handle.read(ZIP_TAIL_BYTES)
    except OSError:
        return None
    category = _zip_category(tail)
    if category == "archive":
        return None
    return Detection(category, detection.source, CATEGORIES.get(category, category), CATEGORY_EXTENSIONS.get(category, ()))


def _from_extension(extension: str | None) -> Detection:
    """Last resort: trust the suffix only when it is one we recognise."""
    clean_extension = _clean_extension(extension)
    if not clean_extension:
        return Detection(UNKNOWN, "extension", CATEGORIES[UNKNOWN], ())
    for category, extensions in CATEGORY_EXTENSIONS.items():
        if clean_extension in extensions:
            return Detection(category, "extension", CATEGORIES.get(category, category), extensions)
    return Detection(UNKNOWN, "extension", CATEGORIES[UNKNOWN], ())


def detect_from_virustotal(report: dict | None) -> Detection | None:
    """Classify from VirusTotal's own analysis of the file.

    VT parses container formats and interpreters far deeper than a header sniff
    can, so its verdict is preferred when the file has never been seen before
    and magic bytes came back unknown.
    """
    if not report:
        return None
    attributes = report.get("data", {}).get("attributes", {})
    if not attributes:
        attributes = report.get("file_info", {}) if isinstance(report.get("file_info"), dict) else {}
    if not attributes:
        return None

    tags = [str(tag).lower() for tag in (attributes.get("type_tags") or [])]
    for tag in tags:
        category = _VT_TAG_TO_CATEGORY.get(tag)
        if category:
            return Detection(category, "virustotal", CATEGORIES.get(category, category), CATEGORY_EXTENSIONS.get(category, ()))

    description = str(attributes.get("type_description") or "").lower()
    for pattern, category in _VT_DESCRIPTION_TO_CATEGORY:
        if re.search(pattern, description):
            return Detection(category, "virustotal", CATEGORIES.get(category, category), CATEGORY_EXTENSIONS.get(category, ()))
    return None


def resolve(
    path: str | Path,
    extension: str | None = None,
    virustotal_report: dict | None = None,
) -> Detection:
    """Best available classification, in descending order of trustworthiness.

    Content sniffing wins because it is local and cheap. VT is consulted only
    when magic bytes were inconclusive. The filename is a last resort and is
    the only source that can be spoofed, which `is_spoofed` reports on.
    """
    magic = detect_from_file(path, extension)
    if magic.category != UNKNOWN:
        return magic

    if virustotal_report:
        from_vt = detect_from_virustotal(virustotal_report)
        if from_vt and from_vt.category != UNKNOWN:
            return from_vt

    return _from_extension(extension)


def is_spoofed(claimed_extension: str | None, detection: Detection) -> bool:
    """True when the uploaded suffix contradicts what the bytes say.

    Only a suffix the taxonomy knows counts as a contradiction. A `.weird` or
    extensionless upload is merely unrecognised, not evidence of deception, and
    an extensionless script is a perfectly normal thing to submit.
    """
    claimed = _clean_extension(claimed_extension)
    if not claimed or detection.source == "extension":
        return False
    if detection.contradicted_binary_claim:
        return True
    if detection.category == UNKNOWN:
        return False
    if claimed not in _EXTENSION_OWNER:
        return False
    return _EXTENSION_OWNER[claimed] != detection.category


def summarize(categories: Iterable[str]) -> list[dict]:
    """Category rows for the dashboard, ordered by dangerous average then volume."""
    return [
        {"category": category, "label": CATEGORIES.get(category, category)}
        for category in sorted(set(categories))
    ]
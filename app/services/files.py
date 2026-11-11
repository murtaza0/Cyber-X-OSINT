import hashlib
import zipfile
from pathlib import Path
from PIL import Image, ExifTags
from pypdf import PdfReader
from docx import Document
from openpyxl import load_workbook
from pptx import Presentation

Image.MAX_IMAGE_PIXELS = 40_000_000

def validate_container(path: Path):
    if path.suffix.lower() not in {".docx", ".xlsx", ".pptx"}:
        return
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > 2000:
                raise ValueError("Office document contains too many archive entries")
            total = sum(info.file_size for info in infos)
            if total > 100 * 1024 * 1024:
                raise ValueError("Office document expands beyond the 100 MB safety limit")
            for info in infos:
                if info.file_size > 25 * 1024 * 1024:
                    raise ValueError("Office document contains an oversized embedded part")
                if info.compress_size and info.file_size / info.compress_size > 150:
                    raise ValueError("Office document has a suspicious compression ratio")
    except zipfile.BadZipFile as exc:
        raise ValueError("Invalid Office document archive") from exc


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def extract_file_metadata(path: Path, filename: str) -> dict:
    validate_container(path)
    suffix = path.suffix.lower()
    result = {"filename": filename, "extension": suffix, "size_bytes": path.stat().st_size}
    if suffix in {".jpg", ".jpeg", ".png", ".tiff", ".webp"}:
        with Image.open(path) as img:
            result.update({"format": img.format, "dimensions": list(img.size), "mode": img.mode})
            try:
                exif = img.getexif()
                decoded = {}
                for key, value in exif.items():
                    label = ExifTags.TAGS.get(key, str(key))
                    decoded[label] = str(value)[:500]
                result["exif"] = decoded
                # Decode embedded GPS only when the original file actually contains it.
                gps_ifd = exif.get_ifd(34853) if hasattr(exif, "get_ifd") else {}
                if gps_ifd:
                    gps = {ExifTags.GPSTAGS.get(k, str(k)): v for k, v in gps_ifd.items()}
                    def to_decimal(parts, ref):
                        numbers = [float(x) for x in parts]
                        value = numbers[0] + numbers[1] / 60 + numbers[2] / 3600
                        return -value if str(ref).upper() in {"S", "W"} else value
                    if gps.get("GPSLatitude") and gps.get("GPSLatitudeRef") and gps.get("GPSLongitude") and gps.get("GPSLongitudeRef"):
                        result["embedded_gps"] = {
                            "latitude": to_decimal(gps["GPSLatitude"], gps["GPSLatitudeRef"]),
                            "longitude": to_decimal(gps["GPSLongitude"], gps["GPSLongitudeRef"]),
                        }
            except Exception:
                result["exif"] = {}
    elif suffix == ".pdf":
        reader = PdfReader(str(path), strict=False)
        metadata = reader.metadata
        result["pages"] = len(reader.pages)
        result["document_metadata"] = {str(k): str(v)[:500] for k, v in (metadata or {}).items()}
        text = "\n".join((page.extract_text() or "") for page in reader.pages[:10])
        result["text_excerpt"] = text[:5000]
    elif suffix == ".docx":
        doc = Document(str(path))
        result["paragraph_count"] = len(doc.paragraphs)
        result["text_excerpt"] = "\n".join(p.text for p in doc.paragraphs[:100])[:5000]
        props = doc.core_properties
        result["document_metadata"] = {"author": props.author, "title": props.title, "subject": props.subject, "created": str(props.created), "modified": str(props.modified)}
    elif suffix == ".xlsx":
        wb = load_workbook(path, read_only=True, data_only=True)
        result["sheets"] = [{"name": ws.title, "max_row": ws.max_row, "max_column": ws.max_column} for ws in wb.worksheets]
        excerpt = []
        for ws in wb.worksheets[:5]:
            for row in ws.iter_rows(min_row=1, max_row=min(ws.max_row, 20), values_only=True):
                excerpt.append(" | ".join(str(v) for v in row if v is not None))
        result["text_excerpt"] = "\n".join(excerpt)[:5000]
        wb.close()
    elif suffix == ".pptx":
        prs = Presentation(str(path))
        texts = []
        for slide in prs.slides:
            for shape in slide.shapes:
                if getattr(shape, "has_text_frame", False): texts.append(shape.text)
        result["slides"] = len(prs.slides)
        result["text_excerpt"] = "\n".join(texts)[:5000]
    elif suffix in {".txt", ".md", ".csv", ".json", ".xml", ".log"}:
        result["text_excerpt"] = path.read_text(encoding="utf-8", errors="replace")[:5000]
    else:
        result["note"] = "File hash and basic metadata only; format not parsed."
    return result

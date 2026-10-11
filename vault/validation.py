import base64
import io
import json
import os
import runpy
import subprocess
import sys
import warnings
from pathlib import Path

from django.conf import settings
from PIL import Image, ImageOps
from pypdf import PdfReader


class InvalidUpload(ValueError):
    pass


class ProcessingBusy(InvalidUpload):
    pass


def inspect_file(path, original_name):
    return isolated_inspection(path, original_name)


def isolated_inspection(path, original_name, thumbnail=False):
    limits = {
        "pixels": settings.MAX_IMAGE_PIXELS,
        "pages": settings.MAX_PDF_PAGES,
        "thumbnail": thumbnail,
        "sandbox": settings.PRODUCTION,
    }
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in {"SYSTEMROOT", "SystemRoot", "TEMP", "TMP"}
    }
    try:
        from vault.processing import parser_slot

        with parser_slot():
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(Path(__file__).resolve()),
                    str(path),
                    original_name,
                    json.dumps(limits),
                ],
                capture_output=True,
                timeout=15,
                env=environment,
            )
        if result.returncode != 0:
            raise InvalidUpload("The file is malformed or exceeds processing limits.")
        data = json.loads(result.stdout)
        if "error" in data:
            raise InvalidUpload(data["error"])
        if thumbnail:
            return data["mime"], data["pages"], base64.b64decode(data["thumbnail"])
        return data["mime"], data["pages"]
    except (subprocess.TimeoutExpired, ValueError, KeyError) as exc:
        if isinstance(exc, InvalidUpload):
            raise
        raise InvalidUpload("The file is malformed or exceeds processing limits.") from exc


def inspect_untrusted(path, original_name, max_pixels, max_pages):
    extension = Path(original_name).suffix.lower()
    with path.open("rb") as stream:
        header = stream.read(16)
    allowed = {
        ".pdf": "application/pdf",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".webp": "image/webp",
    }
    if extension not in allowed:
        raise InvalidUpload("Only PDF, JPEG, PNG, and WebP files are supported.")
    mime = allowed[extension]
    try:
        if extension == ".pdf":
            if not header.startswith(b"%PDF-"):
                raise InvalidUpload("File content does not match its extension.")
            reader = PdfReader(path, strict=True)
            if reader.is_encrypted:
                raise InvalidUpload("Encrypted PDFs are unsupported.")
            pages = len(reader.pages)
            if not 1 <= pages <= max_pages:
                raise InvalidUpload("PDF exceeds the page limit or contains no pages.")
            # Reject embedded active actions/attachments rather than passing them to a browser.
            forbidden = {
                "/JavaScript",
                "/JS",
                "/Launch",
                "/EmbeddedFiles",
                "/OpenAction",
                "/AA",
                "/RichMedia",
            }
            visited = set()

            def walk(obj, depth=0):
                if depth > 80 or len(visited) > 100000:
                    raise InvalidUpload("PDF structure exceeds processing limits.")
                identity = id(obj)
                if identity in visited:
                    return
                visited.add(identity)
                if hasattr(obj, "get_object"):
                    resolved = obj.get_object()
                    if resolved is not obj:
                        walk(resolved, depth + 1)
                        return
                if isinstance(obj, dict):
                    if forbidden.intersection(obj.keys()):
                        raise InvalidUpload("PDF contains unsupported active content.")
                    for value in obj.values():
                        walk(value, depth + 1)
                elif isinstance(obj, (list, tuple)):
                    for value in obj:
                        walk(value, depth + 1)

            walk(reader.trailer)
            return mime, pages
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(path) as image:
                expected = {"image/jpeg": "JPEG", "image/png": "PNG", "image/webp": "WEBP"}[mime]
                if image.format != expected or image.width * image.height > max_pixels:
                    raise InvalidUpload("Image content or dimensions are unsupported.")
                if getattr(image, "n_frames", 1) > 1:
                    raise InvalidUpload("Animated images are unsupported.")
                image.verify()
            with Image.open(path) as image:
                image.load()
        return mime, 1
    except InvalidUpload:
        raise
    except Exception as exc:
        raise InvalidUpload("The file is malformed or unsupported.") from exc


if __name__ == "__main__":
    if sys.platform != "win32":
        import resource

        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    try:
        options = json.loads(sys.argv[3])
        path = Path(sys.argv[1])
        if options.get("sandbox"):
            sandbox = runpy.run_path(str(Path(__file__).with_name("parser_sandbox.py")))
            sandbox["restrict_parser"](path)
        mime, pages = inspect_untrusted(path, sys.argv[2], options["pixels"], options["pages"])
        thumbnail = b""
        if options["thumbnail"] and mime.startswith("image/"):
            with Image.open(path) as image:
                image = ImageOps.exif_transpose(image).convert("RGB")
                image.thumbnail((400, 300))
                buffer = io.BytesIO()
                image.save(buffer, format="JPEG", quality=80)
                thumbnail = buffer.getvalue()
        print(
            json.dumps(
                {"mime": mime, "pages": pages, "thumbnail": base64.b64encode(thumbnail).decode()}
            )
        )
    except InvalidUpload as exc:
        print(json.dumps({"error": str(exc)}))
    except Exception:
        print(json.dumps({"error": "The file is malformed or unsupported."}))

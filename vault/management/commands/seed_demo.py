import io
import json
import os
import secrets

from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management.base import BaseCommand, CommandError
from PIL import Image, ImageDraw
from pypdf import PdfWriter
from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject

from accounts.models import User
from vault.models import Folder, FolderGrant
from vault.services import upload_document


class Command(BaseCommand):
    help = "Create development-only synthetic documents and random demo credentials."

    def handle(self, *args, **options):
        if settings.PRODUCTION:
            raise CommandError("Demo data is forbidden in production")
        if User.objects.filter(username__in=["demo.admin", "demo.staff", "demo.other"]).exists():
            raise CommandError("Demo users already exist; existing credentials are not changed")
        credentials = {}
        for name, role in [
            ("demo.admin", User.Role.ADMIN),
            ("demo.staff", User.Role.STAFF),
            ("demo.other", User.Role.STAFF),
        ]:
            password = secrets.token_urlsafe(24)
            user = User.objects.create_user(name, password=password, role=role)
            credentials[name] = password
            if role == User.Role.ADMIN:
                admin = user
            elif name == "demo.staff":
                staff = user
        folder = Folder.objects.create(name="Programme documents")
        FolderGrant.objects.create(folder=folder, user=staff)
        Folder.objects.create(name="Administration")
        Folder.objects.create(name="Finance & operations")
        writer = PdfWriter()
        for number in range(1, 3):
            page = writer.add_blank_page(width=612, height=792)
            font = DictionaryObject(
                {
                    NameObject("/Type"): NameObject("/Font"),
                    NameObject("/Subtype"): NameObject("/Type1"),
                    NameObject("/BaseFont"): NameObject("/Helvetica"),
                }
            )
            page[NameObject("/Resources")] = DictionaryObject(
                {
                    NameObject("/Font"): DictionaryObject(
                        {NameObject("/F1"): writer._add_object(font)}
                    )
                }
            )
            content = DecodedStreamObject()
            content.set_data(
                f"BT /F1 22 Tf 60 700 Td (SSDC - Synthetic programme report) Tj 0 -42 Td /F1 12 Tf (Demo page {number}. No real organizational data.) Tj ET".encode()
            )
            page[NameObject("/Contents")] = writer._add_object(content)
        buffer = io.BytesIO()
        writer.write(buffer)
        pdf = upload_document(
            admin,
            folder,
            SimpleUploadedFile("programme-report.pdf", buffer.getvalue()),
            "Programme overview - sample report",
        )
        image = Image.new("RGB", (1200, 800), "#e4ebdc")
        draw = ImageDraw.Draw(image)
        draw.rectangle((140, 120, 1060, 680), fill="#f8faf3", outline="#72966d", width=4)
        draw.text((190, 210), "SSDC DOCUMENT VAULT", fill="#215d48", font_size=45)
        draw.text((190, 300), "Synthetic image for preview testing", fill="#74856f", font_size=28)
        draw.text((190, 470), "No real organizational records", fill="#74856f", font_size=24)
        buffer = io.BytesIO()
        image.save(buffer, "PNG")
        photo = upload_document(
            admin,
            folder,
            SimpleUploadedFile("sample-workspace.png", buffer.getvalue()),
            "Workspace illustration - sample image",
        )
        credentials["pdf_id"] = str(pdf.document_id)
        credentials["image_id"] = str(photo.document_id)
        credentials["folder_id"] = str(folder.pk)
        destination = settings.BASE_DIR / "artifacts" / "demo-credentials.json"
        destination.parent.mkdir(exist_ok=True)
        with os.fdopen(
            os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
        ) as stream:
            json.dump(credentials, stream, indent=2)
        self.stdout.write(
            "Synthetic demo created. Credentials are in artifacts/demo-credentials.json (gitignored)."
        )

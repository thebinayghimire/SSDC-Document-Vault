"""Fail multipart intake cleanly if its temporary filesystem cannot accept bytes."""

import logging

from django.conf import settings
from django.core.files.uploadhandler import (
    FileUploadHandler,
    StopUpload,
    TemporaryFileUploadHandler,
)


class UploadBudgetHandler(FileUploadHandler):
    """Bound all file bytes before either Django storage handler receives them."""

    def __init__(self, request=None):
        super().__init__(request)
        self.received = 0
        self.files = 0

    def new_file(self, *args, **kwargs):
        super().new_file(*args, **kwargs)
        self.files += 1
        if self.files > 1:
            self.reject()

    def reject(self):
        self.request.upload_limit_exceeded = True
        raise StopUpload(connection_reset=False)

    def receive_data_chunk(self, raw_data, start):
        self.received += len(raw_data)
        if self.received > settings.MAX_UPLOAD_BYTES:
            self.reject()
        return raw_data

    def file_complete(self, file_size):
        return None


class BudgetedTemporaryFileUploadHandler(TemporaryFileUploadHandler):
    def failed(self):
        self.request.upload_storage_unavailable = True
        if getattr(self, "file", None) is not None:
            self.file.close()
        logging.getLogger(__name__).error(
            "Upload temporary storage unavailable", extra={"event_code": "upload_temp_unavailable"}
        )
        raise StopUpload(connection_reset=False)

    def new_file(self, *args, **kwargs):
        try:
            return super().new_file(*args, **kwargs)
        except OSError:
            self.failed()

    def receive_data_chunk(self, raw_data, start):
        try:
            return super().receive_data_chunk(raw_data, start)
        except OSError:
            self.failed()

    def file_complete(self, file_size):
        try:
            return super().file_complete(file_size)
        except OSError:
            self.failed()

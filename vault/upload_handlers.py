"""Fail multipart intake cleanly if its temporary filesystem cannot accept bytes."""

import logging

from django.core.files.uploadhandler import StopUpload, TemporaryFileUploadHandler


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

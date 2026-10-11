import json
import logging
import re
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path

request_reference = ContextVar("request_reference", default=None)


class SafeJSONFormatter(logging.Formatter):
    def format(self, record):
        # Avoid request objects, exception locals, credentials, and arbitrary messages.
        data = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": getattr(
                record,
                "event_code",
                "application_error" if record.levelno >= 40 else "application_event",
            ),
            "request_id": request_reference.get(),
            "location": f"{Path(record.pathname).name}:{record.lineno}:{record.funcName}",
            "exception_type": record.exc_info[0].__name__ if record.exc_info else None,
        }
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", str(data["event"])):
            data["event"] = "application_error"
        request = getattr(record, "request", None)
        if request is not None:
            data["request_id"] = getattr(request, "request_id", data["request_id"])
        status = getattr(record, "status_code", None)
        if isinstance(status, int):
            data["status"] = status
        if record.exc_info and record.exc_info[2]:
            stack, traceback = [], record.exc_info[2]
            while traceback:
                code = traceback.tb_frame.f_code
                stack.append(f"{Path(code.co_filename).name}:{traceback.tb_lineno}:{code.co_name}")
                traceback = traceback.tb_next
            data["stack"] = stack[-20:]
        return json.dumps(data)

import json
import logging


class SafeJSONFormatter(logging.Formatter):
    def format(self, record):
        # Avoid request objects, exception locals, credentials, and arbitrary messages.
        return json.dumps(
            {
                "level": record.levelname,
                "logger": record.name,
                "event": "application_error" if record.levelno >= 40 else "application_event",
                "exception_type": record.exc_info[0].__name__ if record.exc_info else None,
            }
        )

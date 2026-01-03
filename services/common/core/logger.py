import logging
import sys
import os
import json

class JsonFormatter(logging.Formatter):
    """
    Custom formatter to output logs in JSON format for Loki/Grafana ingestion.
    """
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%SZ"),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "func": record.funcName
        }
        # Merge extra fields (metrics) if provided in the log call
        if hasattr(record, 'extra_info') and isinstance(record.extra_info, dict):
            log_record.update(record.extra_info)
        return json.dumps(log_record)

class CustomAdapter(logging.LoggerAdapter):
    """
    Adapter to allow passing 'extra_info' as a keyword argument.
    """
    def process(self, msg, kwargs):
        extra_info = kwargs.pop('extra_info', {})
        # Merge extra_info into the 'extra' dict so it ends up in the LogRecord
        extra = kwargs.get('extra', {})
        if extra_info:
            extra['extra_info'] = extra_info
        
        kwargs['extra'] = extra
        return msg, kwargs

def get_logger(name: str):
    logger = logging.getLogger(name)
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    logger.setLevel(log_level)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        
    logger.propagate = False
    
    # Return CustomAdapter wrapping the logger
    return CustomAdapter(logger, {})

import re
from enum import Enum


class LogLevel(Enum):
    INFO = "INFO"
    WARNING = "WARN"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"


class Log:
    def __init__(self, raw_json: dict):
        self.timestamp = raw_json.get("timestamp")

        lvl = raw_json.get("level") or raw_json.get("level_name") or raw_json.get("severity")
        if lvl is None:
            self.level = LogLevel.UNKNOWN
        else:
            try:
                self.level = LogLevel(lvl)
            except Exception:
                try:
                    self.level = LogLevel[lvl.strip().upper()]
                except Exception:
                    self.level = LogLevel.UNKNOWN

        self.prefix = raw_json.get("prefix")
        self.message = raw_json.get("message")
        self.message_clean = self.message.strip().lower()

    def __str__(self):
        lvl = self.level.value if isinstance(self.level, LogLevel) else str(self.level)
        return f"[{self.timestamp}] [{lvl}] {self.message}"

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "level": self.level.value if isinstance(self.level, LogLevel) else str(self.level),
            "prefix": self.prefix,
            "message": self.message
        }

    def _get_seq_num(self):
        m = re.search(r"\[seq#\s*=\s*(\d+)\]", self.message_clean)
        return int(m.group(1)) if m else None


# -------------------- SERVER LOG -------------------------

class ServerLogType(Enum):
    MSG_RECVD = "[data]"
    ACK_SENT = "[ack]"
    INCORRECT_SEQ_NUM = "incorrect sequence number"


class ServerLog(Log):
    def __init__(self, raw_json):
        super().__init__(raw_json)
        self.type = self.__determine_type()
        self.seq_num = self._get_seq_num()

    def __str__(self):
        return f"[Server] {super().__str__()}"

    def to_dict(self):
        d = super().to_dict()
        d.update({
            "type": self.type.value if self.type else None,
            "seq_num": self.seq_num
        })
        return d

    def __determine_type(self):
        for t in ServerLogType:
            if t.value in self.message_clean:
                return t
        return None


# -------------------- PROXY LOG -------------------------

class ProxyLogType(Enum):
    DATA_RECVD = "[data] packet received"
    DATA_FORWARDED = "[data] packet successfully forwarded"
    DATA_DELAYED = "[data] delaying packet"
    DATA_DROPPED = "[data] packet dropped"
    ACK_RECVD = "[ack] packet received"
    ACK_FORWARDED = "[ack] packet successfully forwarded"
    ACK_DELAYED = "[ack] delaying packet"
    ACK_DROPPED = "[ack] packet dropped"


class ProxyLog(Log):
    def __init__(self, raw_json):
        super().__init__(raw_json)
        self.type = self.__determine_type()
        self.seq_num = self._get_seq_num()

    def __str__(self):
        return f"[Proxy] {super().__str__()}"

    def to_dict(self):
        d = super().to_dict()
        d.update({
            "type": self.type.value if self.type else None,
            "seq_num": self.seq_num
        })
        return d

    def __determine_type(self):
        for t in ProxyLogType:
            if t.value in self.message_clean:
                return t
        return None


# -------------------- CLIENT LOG -------------------------

class ClientLogType(Enum):
    MSG_SENT = "[data] message sent"
    TIMEOUT_REACHED = "[data] timeout reached"
    RETRANSMITTING = "retransmit packet"
    ACK_RECVD = "[ack] ack received"


class ClientLog(Log):
    def __init__(self, raw_json):
        super().__init__(raw_json)
        self.type = self.__determine_type()
        self.seq_num = self._get_seq_num()
        self.retry_attempt_num = self.__get_retry_attempt_count()

    def __str__(self):
        return f"[Client] {super().__str__()}"

    def to_dict(self):
        d = super().to_dict()
        d.update({
            "type": self.type.value if self.type else None,
            "seq_num": self.seq_num,
            "retry_attempt_num": self.retry_attempt_num
        })
        return d

    def __determine_type(self):
        for t in ClientLogType:
            if t.value in self.message_clean:
                return t
        return None

    def __get_retry_attempt_count(self):
        m = re.search(r"attempt\s*#\s*(\d+)", self.message_clean)
        return int(m.group(1)) if m else None

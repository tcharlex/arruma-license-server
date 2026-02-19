import uuid
import hashlib
import os
import platform


def get_machine_id():
    raw = f"{uuid.getnode()}-{platform.node()}-{os.getlogin()}"
    return hashlib.sha256(raw.encode()).hexdigest()

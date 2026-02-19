import uuid
import hashlib
import os
import platform


def get_machine_id():
    try:
        data = [
            str(uuid.getnode()),  # MAC address
            platform.node(),  # Nome do PC
            platform.system(),  # Windows/Linux
            platform.processor(),  # CPU
            os.environ.get("PROCESSOR_IDENTIFIER", ""),
        ]

        raw = "|".join(data)
        return hashlib.sha256(raw.encode()).hexdigest()

    except Exception:
        # fallback caso algo falhe
        return hashlib.sha256(platform.node().encode()).hexdigest()

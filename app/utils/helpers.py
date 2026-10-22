import math
from typing import Union


def format_bytes(size_bytes: Union[int, float]) -> str:
    """
    Format bytes into a human-readable string (e.g. 10.45 MB).
    """
    if size_bytes == 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {units[i]}"

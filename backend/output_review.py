"""Cover a saved, redacted tool output once without repeating it in later plans."""

CHUNK_CHARS = 10000
OVERLAP_CHARS = 250


def chunks(output):
    """Yield overlapping character ranges that cover every character in order."""
    if not isinstance(output, str):
        raise ValueError('Saved output must be text.')
    if not output:
        return
    start = 0
    while start < len(output):
        end = min(start + CHUNK_CHARS, len(output))
        yield start, end, output[start:end]
        if end == len(output):
            break
        start = end - OVERLAP_CHARS

import bleach


def sanitize_input(value, max_length=None):
    if not isinstance(value, str):
        return value
    value = value.strip()
    value = bleach.clean(value, strip=True, tags=[])
    if max_length and len(value) > max_length:
        value = value[:max_length]
    return value

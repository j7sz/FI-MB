import re

HTTP_VERSION_PATTERN = re.compile(rb"HTTP/\d\.\d\r\n")


def find_http_version_blocks(msg: bytes, block_size: int = 16) -> list:
    """Return the 16-byte block(s) that contain the HTTP version string.

    Checks single blocks first, then adjacent pairs if the pattern straddles
    a block boundary.
    """
    blocks = [msg[i:i+block_size] for i in range(0, len(msg), block_size)]

    for block in blocks:
        if HTTP_VERSION_PATTERN.search(block):
            return [block]

    for i in range(len(blocks) - 1):
        if HTTP_VERSION_PATTERN.search(blocks[i] + blocks[i + 1]):
            return [blocks[i], blocks[i + 1]]

    return []


if __name__ == "__main__":
    msg = (b"GET /2115a62/seaaaadndingaoet- HTTP/1.1\r\n"
           b"Host: stackoverflow.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")

    matching = find_http_version_blocks(msg)
    if matching:
        print("Matching block(s):", matching)
        print(b''.join(matching))
    else:
        print("No matching blocks found")

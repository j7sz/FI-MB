import re

msg = b"GET /2115a62/seaaaadndingaoet- HTTP/1.1\r\nHost: stackoverflow.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"

# Split the message into 16-byte blocks
block_size = 16
blocks = [msg[i:i+block_size] for i in range(0, len(msg), block_size)]

# Regular expression to match any HTTP version
http_version_pattern = re.compile(rb"HTTP/\d\.\d\r\n")

# List to store the matching block(s)
matching_blocks = []

# Check each block for the HTTP version pattern
for i in range(len(blocks)):
    if re.search(http_version_pattern, blocks[i]):
        matching_blocks.append(blocks[i])
        break  # Stop after finding the first occurrence

# If no single block was sufficient, check for the pattern across two blocks
if not matching_blocks:
    for i in range(len(blocks) - 1):
        combined = blocks[i] + blocks[i + 1]
        if re.search(http_version_pattern, combined):
            matching_blocks.extend([blocks[i], blocks[i + 1]])
            break  # Stop after finding the first occurrence

# Join the matching blocks and print the result
if matching_blocks:
    print("==============")
    print("The resulting block(s)", matching_blocks)
    print("================")
    result = b''.join(matching_blocks)
    print(result)
else:
    print("No matching blocks found")

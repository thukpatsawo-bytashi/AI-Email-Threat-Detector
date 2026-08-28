# Email Parser

The Email Parser processes raw `.eml` files and converts them into a
standardized Python dictionary for use by the other threat detection modules.

## Usage

```python
from email_parser import parse_email

with open("email.eml", "rb") as f:
    file_data = f.read()

parsed_email = parse_email(file_data)

print(parsed_email)

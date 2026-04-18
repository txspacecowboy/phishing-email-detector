import keyring

SERVICE = "PhishingDetector"
KEY_ADDRESS  = "gmail_address"
KEY_PASSWORD = "gmail_app_password"


def save(address: str, app_password: str):
    keyring.set_password(SERVICE, KEY_ADDRESS,  address)
    keyring.set_password(SERVICE, KEY_PASSWORD, app_password)


def load() -> tuple[str, str]:
    address  = keyring.get_password(SERVICE, KEY_ADDRESS)  or ""
    password = keyring.get_password(SERVICE, KEY_PASSWORD) or ""
    return address, password


def clear():
    try:
        keyring.delete_password(SERVICE, KEY_ADDRESS)
        keyring.delete_password(SERVICE, KEY_PASSWORD)
    except keyring.errors.PasswordDeleteError:
        pass

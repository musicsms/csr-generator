import string
import secrets


def generate_passphrase(length):
    exclude_char = r"\'\`\"\|\;\\\{\}\[\]\(\)\/"
    characters = "".join(set(string.ascii_letters + string.digits + string.punctuation) - set(exclude_char))
    pass_phrase = ''.join(secrets.choice(characters) for _ in range(length))
    return pass_phrase

"""Small complete DER readers for the explicit private preflight key profiles."""


RSA_ALGORITHM = bytes.fromhex('300d06092a864886f70d0101010500')


def der(raw, offset, tag):
    if type(raw) is not bytes or not 0 <= offset < len(raw)-1 or raw[offset] != tag:
        raise ValueError('complete canonical key DER tag required')
    size = raw[offset+1]; start = offset+2
    if size & 0x80:
        count = size & 0x7f
        if not 1 <= count <= 2 or start+count > len(raw) or raw[start] == 0:
            raise ValueError('bounded minimal key DER length required')
        size = int.from_bytes(raw[start:start+count], 'big'); start += count
        if size < 128 or count == 2 and size < 256:
            raise ValueError('nonminimal key DER length')
    if start+size > len(raw):
        raise ValueError('incomplete key DER content')
    return raw[start:start+size], start+size


def positive_integer(raw, offset):
    value, end = der(raw, offset, 2)
    if (not 0 < len(value) <= 1025 or value[0] & 0x80
            or len(value) > 1 and value[0] == 0 and value[1] < 128):
        raise ValueError('bounded minimal positive RSA integer required')
    number = int.from_bytes(value, 'big')
    if number == 0:
        raise ValueError('nonzero RSA component required')
    return number, end


def rsa_components(raw, private):
    body, end = der(raw, 0, 0x30)
    if end != len(raw) or private and not body.startswith(b'\x02\x01\x00'):
        raise ValueError('complete two-prime RSA key required')
    offset = 3 if private else 0; values = []
    for _ in range(8 if private else 2):
        number, offset = positive_integer(body, offset); values.append(number)
    if offset != len(body):
        raise ValueError('additional RSA components unsupported')
    modulus, exponent = values[:2]
    if not 2048 <= modulus.bit_length() <= 8192 or not modulus & 1 or exponent != 65537:
        raise ValueError('RSA modulus 2048..8192 bits and exponent 65537 required')
    return modulus, exponent


def rsa_private(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= 8192:
        raise ValueError('bounded RSA PKCS8 required')
    body, end = der(raw, 0, 0x30); prefix = b'\x02\x01\x00'+RSA_ALGORITHM
    if end != len(raw) or not body.startswith(prefix):
        raise ValueError('exact unencrypted RSA PKCS8 required')
    key, end = der(body, len(prefix), 4)
    if end != len(body):
        raise ValueError('RSA PKCS8 attributes or trailing data unsupported')
    return rsa_components(key, True)


def rsa_public(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= 1100:
        raise ValueError('bounded RSA public SPKI required')
    body, end = der(raw, 0, 0x30)
    if end != len(raw) or not body.startswith(RSA_ALGORITHM):
        raise ValueError('exact RSA public SPKI required')
    key, end = der(body, len(RSA_ALGORITHM), 3)
    if end != len(body) or not key or key[0] != 0:
        raise ValueError('complete RSA public bit string required')
    return rsa_components(key[1:], False)

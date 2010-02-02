
from ._main import (
    RSAKey as _Key,
    RSA_TYPE_PRIVATE as TYPE_PRIVATE,
    RSA_TYPE_PUBLIC as TYPE_PUBLIC,
    RSA_PAD_V1_5 as PAD_V1_5,
    RSA_PAD_OAEP as PAD_OAEP,
    RSA_PAD_PSS as PAD_PSS,
)

class Key(_Key):
    pass
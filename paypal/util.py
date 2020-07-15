import base64
import hashlib
import hmac
import re
import time

md5 = hashlib.md5


# CREDIT TO https://github.com/paypal/python-signature-generator-for-authentication-header

def getSignature(key, sigBase):
    if (len(sigBase) == 0) or (len(key) == 0):
        raise Exception('sigBase', 'isNull')

    hashed = hmac.new(key, sigBase, hashlib.sha1)
    outSig = base64.b64encode(hashed.digest())
    return outSig


def getEncodedString(sIn):
    if (len(sIn) == 0):
        raise Exception('sIn', 'isNull')

    sOut = ""
    exp = re.compile(r'([A-Za-z0-9_]+)')

    for c in sIn:
        if re.match(exp, c) is None:
            sOut = sOut + "%" + hex(ord(c))[2:]
        elif c == ' ':
            sOut = sOut + "+"
        else:
            sOut = sOut + c

    return sOut


def getAppendedStr(sIn, sParam):
    if ((len(sIn) == 0) | (len(sParam) == 0)):
        raise Exception('sIn', 'isNull')

    return (sIn + "&" + sParam)


def getAuthHeader(apiUser, apiPass, accessTok, secTok, httpMethod, scriptURI):
    oauthVer = "1.0"
    oauthSigMethod = "HMAC-SHA1"
    timeStamp = int(time.time())

    # used to sign the signature base below to build the final signature
    key = apiPass
    key = getAppendedStr(key, getEncodedString(secTok))
    key = str(key)

    sigBase = httpMethod
    sigBase = getAppendedStr(sigBase, getEncodedString(scriptURI))

    # now, NVP params
    sigParm = "oauth_consumer_key=" + apiUser
    sigParm = getAppendedStr(sigParm, "oauth_signature_method=" + oauthSigMethod)
    sigParm = getAppendedStr(sigParm, "oauth_timestamp=" + str(timeStamp))
    sigParm = getAppendedStr(sigParm, "oauth_token=" + accessTok)
    sigParm = getAppendedStr(sigParm, "oauth_version=" + oauthVer)
    # encode and append
    sigBase = getAppendedStr(sigBase, getEncodedString(sigParm))

    sigFinal = getSignature(key, sigBase)

    return (str(timeStamp), sigFinal)

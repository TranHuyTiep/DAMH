import collections
import hashlib
import random
import hmac
import binascii
import json
import can_bac_hai_ecc as can_bac_hai

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b SEED c g n h')

curve = EllipticCurve(
    'secp256k1',
    p=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
    a=-3,
    b= 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
    SEED = 0xbd71344799d5c7fcdc45b59fa3b9ab8f6a948bc5,
    c = 0x5b056c7e11dd68f40469ee7f3c7a7d74f7d121116506d031218291fb,
    g=(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
       0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),
    n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
    h=1,
)



# Tinh module nghic deo k mod p voi eletic mo rong

def inverse_mod(k, p):

    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)

    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    gcd, x, y = old_r, old_s, old_t

    assert gcd == 1
    assert (k * x) % p == 1

    return x % p

# print(inverse_mod(8,11))

# y^2 = x^3 +ax + b
#check point
def is_on_curve(point):
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        # None represents the point at infinity.
        return True

    x, y = point
    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


#  """tra ve -point."""
def point_neg(point):
    if (point):
        x, y = point
        templ =  (x,(-y)%curve.p)
        if(is_on_curve(templ)):
            return templ
        else: return False
    else:
        return None

#add point xem trong thuat toan tinh tong 2 diem trong ecc

def add_point(point1,point2):
    assert is_on_curve(point1)
    assert is_on_curve(point2)

    if(point1) is None:
        return point2
    if(point2) is None:
        return point1

    x1,y1 = point1
    x2,y2 = point2

    if(x1 == x2) and (y1!=y2):
        return None

    if(x1 == x2) and (y1==y2):
        a = (3*(x1*x1)+curve.a)
        b = 2*y1
        m = a*inverse_mod(b,curve.p)
    else:
        a = y2 - y1
        b = x2 - x1
        m = a*inverse_mod(b,curve.p)
    x = m * m - x1 - x2
    y = m * (x1 - x) -y1

    assert (is_on_curve((x,y)))
    return (x%curve.p,y%curve.p)

#public_key = k.point(G)

def scalar_mult(k, point):
    assert is_on_curve(point)

    if(k%curve.n == 0 or point is None):
        return None
    if(k<0):
        scalar_mult(-k,point_neg(point))
    result = None
    templ = point

    while k:
        if(k&1):
            result = add_point(result,templ)

        templ = add_point(templ, templ)

        k>>=1;

    assert is_on_curve(result)
    return result

# tao cap khoa
def make_keypair():
    private_key = random.randrange(1, curve.n)
    public_key = scalar_mult(private_key, curve.g)
    if (public_key[1] % 2 == 0):
        return private_key,public_key[0] * 10;
    else:
        return private_key,public_key[0] * 10 + 1;

##toa do x thanh (x,y)
def x_to_Point(x):
    check = x % 10
    x = x//10
    Y = (x * x * x + curve.a * x + curve.b)%curve.p
    y = can_bac_hai.can_bac_hai(Y,curve.p)
    if(y%2 == check):
        return (x,y)
    else:
        return (x,curve.p-y)



#hash message(enconde)
def hash_message(message):
    # message = message.encode()
    mes_hash = hashlib.sha512(message).digest()
    mes_inter = int.from_bytes(mes_hash,'big')
    mes = mes_inter >> (mes_inter.bit_length() - curve.n.bit_length())
    return mes

#sign chu ky trong ecc
def sign_message(private_key,message):
    r,s = (0,0)
    z = hash_message(message)
    # private_key =  int(private_key,16)
    while not r and not s:
        k = random.randrange(1, curve.n)
        p = scalar_mult(k, curve.g)
        r = p[0] % curve.n
        s = inverse_mod(k,curve.n)*(z+r*private_key)%curve.n
    return (r,s)


#verify

def verify_sign(public_key, message, signature):
    public_key = x_to_Point(public_key)
    if(is_on_curve(public_key) is False):
        return 'invalid'
    r,s = signature

    if(r>curve.n or s>curve.n):
        return 'invalid'

    e = hash_message(message)
    w = inverse_mod(s,curve.n)
    u1 = (e*w)%curve.n
    u2 = (r*w)%curve.n
    O = add_point(scalar_mult(u1,curve.g),scalar_mult(u2,public_key))
    x,y = O
    if (r % curve.n) == (x % curve.n):
        return 'valid'
    else:
        return 'invalid'


# print(private_key)
# sign = sign_message(private_key,'aaaa')
# print(sign)
# print(verify_sign(public_key,'aaaa',sign))

# print(make_keypair())
# cert id:id cua client,
# C = cG
# R = rG
# P = R + kG.
# s = k + H(P, I)c mod n,
# c = random.randrange(1, curve.n)
# C = scalar_mult(c, curve.g)


# create cert
def create_cert(id,public_key_client,private_key_CA,public_key_CA):
    c = private_key_CA
    C = x_to_Point(public_key_CA)
    R = x_to_Point(public_key_client)
    k = random.randrange(1, curve.n)
    P = add_point(R,scalar_mult(k,curve.g))
    a = str(P[0]).encode() + (id)
    s = hashlib.sha256(a).digest()
    s = int.from_bytes(s, 'big')
    if (P[1] % 2 == 0):
        return (P[0] * 10,id,(s*k + c)%curve.n)
    else:
        return (P[0] * 10+1,id,(s*k + c)%curve.n)

# tin lai khoa tu cert
def create_key_to_cert(private_key,public_key_CA,cert):
    P,id,s = cert
    P = x_to_Point(P)
    public_key_CA = x_to_Point(public_key_CA)
    a =str(P[0]).encode() + (id)
    hash_P = hashlib.sha256(a).digest()
    hash_P_i = int.from_bytes(hash_P, 'big')
    b = (hash_P_i*private_key + s) % curve.n
    B = add_point(public_key_CA,scalar_mult(hash_P_i,P))
    check =  scalar_mult(b,curve.g)

    if (B[1] % 2 == 0):
        return b, B[0] * 10,check==B;
    else:
        return b, B[0] * 10 + 1,check==B;
    # return b,B,check==B
# print(create_key_to_cert(private_key,public_key,cert))
#hmac
#
# def hmac(key,message):
#     message = message.encode()
#     if(len(message)>32):
#         key = hashlib.sha256(key).digest()
#     if(len(message)<32):
#         add_block = '0'*(32-len(key))
#         key = key + add_block.encode()
#     o_key_pad = int.from_bytes((bytes.fromhex('5c' * 32)),'big') ^ int.from_bytes(key,'big')
#     i_key_pad = int.from_bytes((bytes.fromhex('36' * 32)), 'big') ^ int.from_bytes(key, 'big')
#     return hashlib.sha256(o_key_pad.to_bytes(32, byteorder='big') + hashlib.sha256((i_key_pad.to_bytes(32, byteorder='big') + message)).digest()).digest()
#     # return i_key_pad.to_bytes(32, byteorder='big') + message
# print(hmac(b'key','The quick brown fox jumps over the lazy dog').hex())

# private_key_cert,public_key_cert = create_key_to_cert(private_key,public_key,cert)
# B= rG + (k + H(P, I)c)G = public_key + cert*G
# tinh khoa tu ben thu 3
def create_key_to_third_party(public_key_CA,id,P):
    # P, id, s = cert
    public_key_CA = x_to_Point(public_key_CA)
    P = x_to_Point(P)
    a = str(P[0]).encode() + (id).encode()
    hash_P = hashlib.sha256(a).digest()
    hash_P_i = int.from_bytes(hash_P, 'big')
    public_key = add_point(public_key_CA, scalar_mult(hash_P_i, P))
    if (public_key[1] % 2 == 0):
        return public_key[0] * 10
    else:
        return public_key[0] * 10 + 1

# tao khoa public tu khoa bi mat
def make_public_key(private_key):
    public_key = scalar_mult(private_key,curve.g)
    if (public_key[1] % 2 == 0):
        return public_key[0] * 10;
    else:
        return public_key[0] * 10 + 1;

# private_key,public_key = make_keypair()
# # print(private_key,public_key )
# private_key = 68537785943445957390070393069201060140134624448744699898339417356543342619139
# public_key = 754310038029066392028554932275352308423639400149113357851795145296806618999321
# a = 483660952981732867406743740858667548923206169871659386247570893174275333083890
#
# # print (make_public_key(private_key))
#
# private_key_CA,public_key_CA = make_keypair()
# cert = (create_cert(b'Hello client',public_key,private_key_CA,public_key_CA))
# b,B,f = create_key_to_cert(private_key,public_key_CA,cert)
# print(cert)
# # print(b,B,f)
# print(create_key_to_third_party(public_key_CA,cert))
# a = b'734094368413402745248246225420036830997793844421753261558905224574286217914420'
# print(int(a)+61)



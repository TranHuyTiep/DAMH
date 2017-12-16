
# n^e module p
def tinh_luy_thua(n,e,p):
    result = 1
    while e != 0:
        if(e%2 == 1):
            result = result*n%p
            e = (e - 1)
        n = n*n%p
        e = e//2
    return result

#phep chia da thuc trong GF(2)
# c(x) = a(x)*b(x) mod q(x)
# a(x) = a[1]x + a[0] and b(x) = b[1]x + b[0]
# q(x) = x^2 + q[1]x + q[0]
def division(a,b,q,p):
    t0 = (a[0] * b[0]) % p
    t1 = (a[0] * b[1] + a[1] * b[0]) % p
    t2 = (a[1] * b[1]) % p
    c1 = (t1 - (q[1]*t2)) % p
    c0 = (t0 - (q[0]*t2)) % p
    return (c0,c1)

# F(x)^e module q(x) in GF(2)
# q(x) = x**2 − bx + c
# c(x) := x^e mod (x^2 − bx + c) = c1*x + c0
# x^e = (x + 0)*(0x + 1)=>a=(1,0),b=(0,1)
#q(-b,c)

def tinh_luy_thua_F(e,a,q,p):
    result = [1,0]
    sq = a
    while e != 0:
        if(e%2 == 1):
            result = division(a,result,q,p)
            e = (e-1)
        a = division(a, a, q, p)
        e = e//2

    return result

#Cipolla-Lehmer square root algorithm
#h := (b^2 − 4c)^(p−1)/2(mod p)

def CL(c, b, p):
    h = (b*b - 4*c) % p
    h1 = tinh_luy_thua(h,(p-1)//2,p)
    s = 1
    if(h1 == 1 or h1 == 0):
        s = 0
    b = (-b) % p
    c = c % p
    q = (c,b)
    e = (p+1)//2
    a = (0,1)       ##x1 = x
    y = tinh_luy_thua_F(e,a,q,p)
    return s * y[0]


#a prime p where p > 2, a quadratic residue c in GF(p) and an integer
# b where 0 < b < p
def can_bac_hai(c,p):
    b = 100
    t = 0
    c = c % p
    for i in range(b):
        y = CL(c, ((i + 1) % p), p)
        t1 = (y * y) % p
        if (t1 == c):
            t = y
            break
    return (t)

# p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
# c = 54482837085503842457913951049488513539071978307250707216928124062793075562515
# t = can_bac_hai(c, p)
# print(t)
# thua toan tinh can bac hai Cipolla-Lehme

/**
 * Created by huytiep on 23/10/2017.
 */
var bignum = require('bignum');
/**
 * n^e module p
 * @param n
 * @param e
 * @param p
 * @returns {*}
 */
function tinh_luy_thua(n,e,p){
    var n = bignum(n)
    var e = bignum(e)
    var p = bignum(p)
    var result = n.powm(e, p)
    return result
}

/**
 * phep chia da thuc trong GF(2)
 # c(x) = a(x)*b(x) mod q(x)
 # a(x) = a[1]x + a[0] and b(x) = b[1]x + b[0]
 # q(x) = x^2 + q[1]x + q[0]
 * @param a
 * @param b
 * @param q
 * @param p
 */

function division(a,b,q,p){
    // console.log(a)
    // console.log(b)
    // console.log(q)
    var t0 = (a[0].mul(b[0])).mod(p)
    var t1 = (a[0].mul( b[1] ).add( a[1].mul(b[0]))).mod(p)
    var t2 = (a[1].mul(b[1])).mod(p)
    var c1 = (t1.sub(q[1].mul(t2))).mod(p)
    var c0 = (t0.sub(q[0].mul(t2))).mod(p)
    return [c0,c1]
}

/**
 * F(x)^e module q(x) in GF(2)
 # q(x) = x**2 − bx + c
 # c(x) := x^e mod (x^2 − bx + c) = c1*x + c0
 # x^e = (x + 0)*(0x + 1)=>a=(1,0),b=(0,1)
 # q(-b,c)
 * @param e
 * @param a
 * @param q
 * @param p
 * @returns {*|Array|[number,number]}
 */
function tinh_luy_thua_F(e,a,q,p){
    var result = [bignum('1'),bignum('0')]
    var sq = a
    // console.log(result)
    while (e.eq(0)==false){
        if(e.mod(2).eq(1)){
            result = division(a,result,q,p)
            e = (e.sub(1))
        }
        a = division(a, a, q, p)
        e = e.div(2)

    }
    return result
}

/**
 * Cipolla-Lehmer square root algorithm
 # h := (b^2 − 4c)^(p−1)/2(mod p)
 * @param c
 * @param b
 * @param p
 * @returns {*}
 * @constructor
 */
function CL(c, b, p){
    var h = (b.mul(b).sub(c.mul(4))).mod(p)
    var h1 = tinh_luy_thua(h, (p.sub(1)).div(2),p)
    var s = bignum('1')
    if(h1.eq(1) || h1.eq(0)){
        s = bignum('0')
    }
    b = ((b).mul(-1)).mod(p)
    c = c.mod(p)
    var q = [c,b]
    var e = (p.add(1)).div(2)
    var a = [bignum('0'),bignum('1')]
    var y = tinh_luy_thua_F(e,a,q,p)
    return (s.mul( y[0]))
}

/**
 * a prime p where p > 2, a quadratic residue c in GF(p) and an integer
 # b where 0 < b < p
 * @param c
 * @param p
 * @returns {*}
 */
function can_bac_hai(c,p) {
    var b = 100
    var t = bignum('0')
    c = c.mod(p)
    for(var i=0;i<b;i++){
        var y = CL(c, (bignum(i + 1).mod(p)), p)
        var t1 = (y.mul(y)).mod(p)
        if (t1.eq(c)){
            t = y
            break
        }
    }
    if(t.gt(0)){
        return (t)
    }else {
        return (t.add(p))
    }
}

module.exports.can_bac_hai = can_bac_hai;


// var p = bignum('115792089210356248762697446949407573530086143415290314195533631308867097853951')
// var c = bignum('54482837085503842457913951049488513539071978307250707216928124062793075562515')
// var t = can_bac_hai(c,p)
//
// console.log(t)
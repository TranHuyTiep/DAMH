var bignum = require('bignum');
var crypto = require('crypto');
var can_bac_hai =  require('./can_bac_hai')


curve = {
    name:'secp256k1',
    p:bignum('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',base=16),
    a:bignum(-3),
    b: bignum('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',base=16),
    SEED : bignum('bd71344799d5c7fcdc45b59fa3b9ab8f6a948bc5',base=16),
    c : bignum('5b056c7e11dd68f40469ee7f3c7a7d74f7d121116506d031218291fb',base=16),
    X:bignum('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',base=16),
    Y:bignum('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',base=16),
    n:bignum('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',base=16),
    h:1,
}

/**
 *
 * @param k
 * @param p
 */
function inverse_mod(k, p) {
    k =  bignum(k)
    p =  bignum(p)
    return k.invertm(p)
}
// console.log(inverse_mod(8,11))


/**
 * y^2 = x^3 +ax + b
 * """Returns True if the given point lies on the elliptic curve."""
 * check point
 * @param point
 */
function is_on_curve(point) {
    if(point.length==null){
        return true
    }
    var x = bignum(point[0])
    var y = bignum(point[1])
    result = y.pow(2)
        .sub(x .pow(3))
        .sub(x.mul(curve.a))
        .sub(curve.b)
        .mod(curve.p);
    return result==0
}

// console.log(is_on_curve([curve.X,curve.Y]))

/**
 *
 * @param point
 */
function point_neg(point){
    if (point.length ==2){
        var x = bignum(point[0])
        var y = bignum(point[1])
        var templ =  [x,(y.neg()).mod(curve.p)]
        if(is_on_curve(templ)){
            return templ
        }else {
            return false
        }
    }else {
        return null
    }
}


/**
 * tong  diem
 * @param point1
 * @param point2
 * @returns {*}
 */
function  add_point(point1,point2) {


    if(point1==null){
        return point2
    }
    if(point2==null) {
        return point1
    }

    if(is_on_curve(point1)==false || is_on_curve(point2)==false){
        return false
    }

    var x1 = point1[0]
    var y1 = point1[1]
    var x2 = point2[0]
    var y2 = point2[1]

    if((x1.eq(x2)==true) && (y1.eq(y2)==false)){
        return None
    }

    if((x1==x2) && (y1==y2)){
        var a = x1.pow(2).mul(3).add(curve.a)
        var b = y1.mul(2)
        var m = a.mul(inverse_mod(b, curve.p))
    }else{
        a = y2.sub(y1)
        b = x2.sub(x1)
        m = a.mul(inverse_mod(b,curve.p))

    }
    var x = m.pow(2).sub(x1).sub(x2)
    var y = m.mul((x1.sub(x))).sub(y1)

    if (is_on_curve((x,y))){
        return [x.mod(curve.p),y.mod(curve.p)]
    }else {
        return null
    }
}


/**
 * tong cua k diem
 * @param k
 * @param point
 * @returns {*}
 */
function scalar_mult(k, point){
    var k = bignum(k)
    if(is_on_curve(point)==false){
        return null
    }

    if(k.mod(curve.n).eq(0) == true || point.length!=2){
        return None
    }

    if(k<0){
        scalar_mult(-k,point_neg(point))
    }
    var resul = null
    var templ = point

    while (k.eq(0)==false){
        if(k.mod(2)==1){
            resul = add_point(resul,templ)
        }
        templ = add_point(templ, templ)

        k=k.shiftRight(1);

    }
    // return result

    if(is_on_curve(resul)) {
        return resul

    }else {
        return null
    }

}

/**
 * tao khoa
 * @returns {*} {public_key,private_key}
 */
function make_keypair(){
    var private_key = curve.n.rand()
    var public_key = scalar_mult(private_key,[curve.X,curve.Y])
    if (public_key[1].mod(2).eq(0)){
        return {private_key:private_key,public_key:public_key[0].mul(10)};
    }else{
        return {private_key:private_key,public_key:public_key[0].mul(10).add(1)};
    }
}


/**
 * x to point public_key
 * @param x
 * @returns {[null,null]} Point(x,y)
 */
function x_to_Point(x){
    var check = x.mod(10)
    var x = x.div(10)
    var Y = (x.pow(3).add(x.mul(curve.a)).add(curve.b)).mod(curve.p)
    var y = can_bac_hai.can_bac_hai(Y,curve.p)
    if(y.mod(2).eq(check)){
        return [x,y]
    }else {
        return [x,curve.p.sub(y)]
    }

}


/**
 * hash sha512
 * @param message
 * @returns {bigInt.BigInteger | *}
 */
function hash_message(message){
    var hash = crypto.createHash('sha512');
    var mes_hash = hash.update(message).digest().toString('hex')
    var mes_inter = bignum(mes_hash,base=16)
    var mes = mes_inter.shiftRight( (mes_inter.bitLength() - curve.n.bitLength()))
    return mes
}

/**
 * sign_message
 * @param private_key
 * @param message
 * @returns {[null,null]} = [r,s]
 */
function sign_message(private_key,message){
    var r = 0,s = 0
    var z = hash_message(message)
// # private_key =  int(private_key,16)
    while (r == 0 || s == 0){
        var k = curve.n.rand()
        var p = scalar_mult(k, [curve.X,curve.Y])
        r = p[0].mod(curve.n)
        s = inverse_mod(k,curve.n).mul(z.add(r.mul(private_key))).mod(curve.n)
    }
    return [r,s]
}

/**
 * verify chu ky
 * @param public_key
 * @param message
 * @param signature
 * @returns {*}
 */
function verify_sign(public_key, message, signature){
    var public_key = x_to_Point(public_key)
    if(is_on_curve(public_key)==false){
        return 'invalid'
    }
    var r = signature[0]
    var s = signature[1]
    if(r.gt(curve.n)|| s.gt(curve.n)){
        return 'invalid'
    }

    var e = hash_message(message)
    var w = inverse_mod(s,curve.n)
    var u1 = (e.mul(w)).mod(curve.n)
    var u2 = (r.mul(w)).mod(curve.n)
    var O = add_point(scalar_mult(u1,[curve.X,curve.Y]),scalar_mult(u2,public_key))
    var x = O[0],y=O[1]
    if (r.mod(curve.n).eq(x.mod(curve.n))){
        return 'valid'
    }else {
        return 'invalid'
    }
}

// var x = make_keypair()
// pub = x.public_key
// pri = x.private_key
// var y = make_keypair()
// var pub_y = y.public_key
// var sign = sign_message(pri,'12222')
// console.log(sign)
// console.log(verify_sign(pub,'12222',sign))

/**
 * tạo cert
 * @param id
 * @param public_key_client
 * @param private_key_CA
 * @param public_key_CA
 * @returns {[null,null,null]}
 */
function create_cert(id,public_key_client,private_key_CA,public_key_CA) {
    var c = private_key_CA
    var C = x_to_Point(public_key_CA)
    var R = x_to_Point(public_key_client)
    var k =  curve.n.rand()
    var P = add_point(R, scalar_mult(k,[curve.X,curve.Y]))
    var a = P[0].toString()
    a = a + id
    var hash = crypto.createHash('sha256');
    var mes_hash = hash.update(a).digest().toString('hex')
    var s = bignum(mes_hash,base=16)
    if (P[1].mod(2).eq(0)) {
        return [P[0].mul(10), id, (s.mul(k).add(c)).mod(curve.n)]
    } else{
        return [P[0].mul(10).add(1), id, (s.mul(k).add(c)).mod(curve.n)]
    }
}


function create_key_to_cert(private_key,public_key_CA,cert) {
    var P = cert[0], id = cert[1],s = cert[2]
    P = x_to_Point(P)
    public_key_CA = x_to_Point(public_key_CA)
    var a = P[0].toString()
    a = a + id
    var hash = crypto.createHash('sha256');
    var mes_hash = hash.update(a).digest().toString('hex')
    var hash_P_i = bignum(mes_hash,base=16)
    var b = (hash_P_i.mul(private_key).add(s)).mod(curve.n)
    B = add_point(public_key_CA, scalar_mult(hash_P_i, P))
    check = scalar_mult(b,[curve.X,curve.Y])
    if (B[1].mod(2).eq(0)){
        return [b, B[0].mul(10), check[0].eq(B[0])];
    }else{
        return [b, B[0].mul(10).add(1), check[0].eq(B[0])];
    }

}





function create_key_to_third_party(public_key_CA,cert){
    var  P = cert[0], id = cert[1],s = cert[2]
    var public_key_CA = x_to_Point(public_key_CA)
    P = x_to_Point(P)
    var a = P[0].toString()
    a = a + id
    var hash = crypto.createHash('sha256');
    var mes_hash = hash.update(a).digest().toString('hex')
    var hash_P_i = bignum(mes_hash,base=16)
    var public_key = add_point(public_key_CA, scalar_mult(hash_P_i, P))
    if (public_key[1].mod(2).eq(0)){
        return public_key[0].mul(10)
    }else{
        return public_key[0].mul(10).add(1)
    }
}

// var client = make_keypair()
// console.log('client',client)
// var ca = make_keypair()
// console.log('ca',ca)
// var private_key=client.private_key,public_key = client.public_key
// var private_key_CA=ca.private_key,public_key_CA = ca.public_key
// cert = (create_cert('Hello client',public_key,private_key_CA,public_key_CA))
// x=create_key_to_cert(private_key,public_key_CA,cert)
// console.log(cert)
// console.log(x)
// console.log(create_key_to_third_party(public_key_CA,cert))
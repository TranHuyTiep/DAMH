
curve = {
    name:'secp256k1',
    p:bigInt('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',base=16),
    a:bigInt(-3),
    b: bigInt('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',base=16),
    SEED : bigInt('bd71344799d5c7fcdc45b59fa3b9ab8f6a948bc5',base=16),
    c : bigInt('5b056c7e11dd68f40469ee7f3c7a7d74f7d121116506d031218291fb',base=16),
    X:bigInt('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',base=16),
    Y:bigInt('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',base=16),
    n:bigInt('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',base=16),
    h:1,
}

/**
 *
 * @param k
 * @param p
 */
function inverse_mod(k, p) {
    k =  bigInt(k)
    p =  bigInt(p)
    return k.modInv(p)
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
    var x = bigInt(point[0])
    var y = bigInt(point[1])
    result = y.pow(2)
        .subtract(x .pow(3))
        .subtract(x.multiply(curve.a))
        .subtract(curve.b)
        .mod(curve.p);
    return result==0
}


/**
 *
 * @param point
 */
function point_neg(point){
    if (point.length ==2){
        var x = bigInt(point[0])
        var y = bigInt(point[1])
        if(y.isNegative()){
            y = y.multiply(-1)
        }
        var templ =  [x,(y).mod(curve.p)]
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
        var a = x1.pow(2).multiply(3).add(curve.a)
        var b = y1.multiply(2)
        var m = a.multiply(inverse_mod(b, curve.p))
    }else{
        a = y2.subtract(y1)
        b = x2.subtract(x1)
        m = a.multiply(inverse_mod(b,curve.p))
    }

    var x = m.pow(2).subtract(x1).subtract(x2)
    var y = m.multiply((x1.subtract(x))).subtract(y1)
    if (is_on_curve((x,y))){
        var y_t = y.mod(curve.p)
        if(y_t.lt(0)){
            return [x.mod(curve.p),curve.p.add(y_t)]
        }else {
            return [x.mod(curve.p),y_t]
        }
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
    var k = bigInt(k)
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
function make_keypair(k){
    var private_key = bigInt('')
    var public_key = [bigInt('')]
    private_key = bigInt.randBetween(0,curve.n)
    if(k){
        private_key = bigInt(k)
    }
    public_key = scalar_mult(private_key,[curve.X,curve.Y])

    if (public_key[1].mod(2).eq(0)){
        return {private_key:private_key.toString(),public_key:public_key[0].multiply(10).toString()};
    }else{
        return {private_key:private_key.toString(),public_key:public_key[0].multiply(10).add(1).toString()};
    }
}



/**
 * x to point public_key
 * @param x
 * @returns {[null,null]} Point(x,y)
 */
function x_to_Point(x){
    x = bigInt(x)
    var check = x.mod(10)
    var x = x.divide(10)
    var Y = (x.pow(3).add(x.multiply(curve.a)).add(curve.b)).mod(curve.p)
    var y = can_bac_hai(Y,curve.p)
    if(y.mod(2).eq(check)){
        return [x,y]
    }else {
        return [x,curve.p.subtract(y)]
    }

}

function create_key_to_third_party(public_key_CA,P,id){
    var public_key_CA = x_to_Point(bigInt(public_key_CA))
    P = x_to_Point(bigInt(P))
    var a = P[0].toString()
    a = a + id
    var mes_hash =  CryptoJS.SHA256(a).toString()
    var hash_P_i = bigInt(mes_hash,base=16)
    var public_key = add_point(public_key_CA, scalar_mult(hash_P_i, P))
    if (public_key[1].mod(2).eq(0)){
        return public_key[0].multiply(10)
    }else{
        return public_key[0].multiply(10).add(1)
    }
}
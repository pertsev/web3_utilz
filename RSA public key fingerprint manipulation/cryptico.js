// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.
// Basic JavaScript BN library - subset useful for RSA encryption.

// Bits per digit
var dbits;

// (public) Constructor

function BigInteger(a, b, c) {
    if (a != null) if ("number" == typeof a) this.fromNumber(a, b, c);
    else if (b == null && "string" != typeof a) this.fromString(a, 256);
    else this.fromString(a, b);
}

// return new, unset BigInteger

function nbi() {
    return new BigInteger(null);
}

// am avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)

function am(i, x, w, j, c, n) {
    var xl = x & 0x7fff,
        xh = x >> 15;
    while (--n >= 0) {
        var l = this[i] & 0x7fff;
        var h = this[i++] >> 15;
        var m = xh * l + h * xl;
        l = xl * l + ((m & 0x7fff) << 15) + w[j] + (c & 0x3fffffff);
        c = (l >>> 30) + (m >>> 15) + xh * h + (c >>> 30);
        w[j++] = l & 0x3fffffff;
    }
    return c;
}

BigInteger.prototype.am = am;
dbits = 30;

BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = ((1 << dbits) - 1);
BigInteger.prototype.DV = (1 << dbits);

var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2, BI_FP);
BigInteger.prototype.F1 = BI_FP - dbits;
BigInteger.prototype.F2 = 2 * dbits - BI_FP;

// Digit conversions
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr, vv;
rr = "0".charCodeAt(0);
for (vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
rr = "a".charCodeAt(0);
for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
rr = "A".charCodeAt(0);
for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

function int2char(n) {
    return BI_RM.charAt(n);
}

function intAt(s, i) {
    var c = BI_RC[s.charCodeAt(i)];
    return (c == null) ? -1 : c;
}

// (protected) copy this to r

function bnpCopyTo(r) {
    for (var i = this.t - 1; i >= 0; --i) r[i] = this[i];
    r.t = this.t;
    r.s = this.s;
}

// (protected) set from integer value x, -DV <= x < DV

function bnpFromInt(x) {
    this.t = 1;
    this.s = (x < 0) ? -1 : 0;
    if (x > 0) this[0] = x;
    else if (x < -1) this[0] = x + DV;
    else this.t = 0;
}

// return bigint initialized to value

function nbv(i) {
    var r = nbi();
    r.fromInt(i);
    return r;
}

// (protected) set from string and radix

function bnpFromString(s, b) {
    var k;
    if (b == 16) k = 4;
    else if (b == 8) k = 3;
    else if (b == 256) k = 8; // byte array
    else if (b == 2) k = 1;
    else if (b == 32) k = 5;
    else if (b == 4) k = 2;
    else {
        this.fromRadix(s, b);
        return;
    }
    this.t = 0;
    this.s = 0;
    var i = s.length,
        mi = false,
        sh = 0;
    while (--i >= 0) {
        var x = (k == 8) ? s[i] & 0xff : intAt(s, i);
        if (x < 0) {
            if (s.charAt(i) == "-") mi = true;
            continue;
        }
        mi = false;
        if (sh == 0) this[this.t++] = x;
        else if (sh + k > this.DB) {
            this[this.t - 1] |= (x & ((1 << (this.DB - sh)) - 1)) << sh;
            this[this.t++] = (x >> (this.DB - sh));
        }
        else this[this.t - 1] |= x << sh;
        sh += k;
        if (sh >= this.DB) sh -= this.DB;
    }
    if (k == 8 && (s[0] & 0x80) != 0) {
        this.s = -1;
        if (sh > 0) this[this.t - 1] |= ((1 << (this.DB - sh)) - 1) << sh;
    }
    this.clamp();
    if (mi) BigInteger.ZERO.subTo(this, this);
}

// (protected) clamp off excess high words

function bnpClamp() {
    var c = this.s & this.DM;
    while (this.t > 0 && this[this.t - 1] == c)--this.t;
}

// (public) return string representation in given radix

function bnToString(b) {
    if (this.s < 0) return "-" + this.negate().toString(b);
    var k;
    if (b == 16) k = 4;
    else if (b == 8) k = 3;
    else if (b == 2) k = 1;
    else if (b == 32) k = 5;
    else if (b == 64) k = 6;
    else if (b == 4) k = 2;
    else return this.toRadix(b);
    var km = (1 << k) - 1,
        d, m = false,
        r = "",
        i = this.t;
    var p = this.DB - (i * this.DB) % k;
    if (i-- > 0) {
        if (p < this.DB && (d = this[i] >> p) > 0) {
            m = true;
            r = int2char(d);
        }
        while (i >= 0) {
            if (p < k) {
                d = (this[i] & ((1 << p) - 1)) << (k - p);
                d |= this[--i] >> (p += this.DB - k);
            }
            else {
                d = (this[i] >> (p -= k)) & km;
                if (p <= 0) {
                    p += this.DB;
                    --i;
                }
            }
            if (d > 0) m = true;
            if (m) r += int2char(d);
        }
    }
    return m ? r : "0";
}

// (public) -this

function bnNegate() {
    var r = nbi();
    BigInteger.ZERO.subTo(this, r);
    return r;
}

// (public) |this|

function bnAbs() {
    return (this.s < 0) ? this.negate() : this;
}

// (public) return + if this > a, - if this < a, 0 if equal

function bnCompareTo(a) {
    var r = this.s - a.s;
    if (r != 0) return r;
    var i = this.t;
    r = i - a.t;
    if (r != 0) return r;
    while (--i >= 0) if ((r = this[i] - a[i]) != 0) return r;
    return 0;
}

// returns bit length of the integer x

function nbits(x) {
    var r = 1,
        t;
    if ((t = x >>> 16) != 0) {
        x = t;
        r += 16;
    }
    if ((t = x >> 8) != 0) {
        x = t;
        r += 8;
    }
    if ((t = x >> 4) != 0) {
        x = t;
        r += 4;
    }
    if ((t = x >> 2) != 0) {
        x = t;
        r += 2;
    }
    if ((t = x >> 1) != 0) {
        x = t;
        r += 1;
    }
    return r;
}

// (public) return the number of bits in "this"

function bnBitLength() {
    if (this.t <= 0) return 0;
    return this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ (this.s & this.DM));
}

// (protected) r = this << n*DB

function bnpDLShiftTo(n, r) {
    var i;
    for (i = this.t - 1; i >= 0; --i) r[i + n] = this[i];
    for (i = n - 1; i >= 0; --i) r[i] = 0;
    r.t = this.t + n;
    r.s = this.s;
}

// (protected) r = this >> n*DB

function bnpDRShiftTo(n, r) {
    for (var i = n; i < this.t; ++i) r[i - n] = this[i];
    r.t = Math.max(this.t - n, 0);
    r.s = this.s;
}

// (protected) r = this << n

function bnpLShiftTo(n, r) {
    var bs = n % this.DB;
    var cbs = this.DB - bs;
    var bm = (1 << cbs) - 1;
    var ds = Math.floor(n / this.DB),
        c = (this.s << bs) & this.DM,
        i;
    for (i = this.t - 1; i >= 0; --i) {
        r[i + ds + 1] = (this[i] >> cbs) | c;
        c = (this[i] & bm) << bs;
    }
    for (i = ds - 1; i >= 0; --i) r[i] = 0;
    r[ds] = c;
    r.t = this.t + ds + 1;
    r.s = this.s;
    r.clamp();
}

// (protected) r = this >> n

function bnpRShiftTo(n, r) {
    r.s = this.s;
    var ds = Math.floor(n / this.DB);
    if (ds >= this.t) {
        r.t = 0;
        return;
    }
    var bs = n % this.DB;
    var cbs = this.DB - bs;
    var bm = (1 << bs) - 1;
    r[0] = this[ds] >> bs;
    for (var i = ds + 1; i < this.t; ++i) {
        r[i - ds - 1] |= (this[i] & bm) << cbs;
        r[i - ds] = this[i] >> bs;
    }
    if (bs > 0) r[this.t - ds - 1] |= (this.s & bm) << cbs;
    r.t = this.t - ds;
    r.clamp();
}

// (protected) r = this - a

function bnpSubTo(a, r) {
    var i = 0,
        c = 0,
        m = Math.min(a.t, this.t);
    while (i < m) {
        c += this[i] - a[i];
        r[i++] = c & this.DM;
        c >>= this.DB;
    }
    if (a.t < this.t) {
        c -= a.s;
        while (i < this.t) {
            c += this[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        c += this.s;
    }
    else {
        c += this.s;
        while (i < a.t) {
            c -= a[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        c -= a.s;
    }
    r.s = (c < 0) ? -1 : 0;
    if (c < -1) r[i++] = this.DV + c;
    else if (c > 0) r[i++] = c;
    r.t = i;
    r.clamp();
}

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.

function bnpMultiplyTo(a, r) {
    var x = this.abs(),
        y = a.abs();
    var i = x.t;
    r.t = i + y.t;
    while (--i >= 0) r[i] = 0;
    for (i = 0; i < y.t; ++i) r[i + x.t] = x.am(0, y[i], r, i, 0, x.t);
    r.s = 0;
    r.clamp();
    if (this.s != a.s) BigInteger.ZERO.subTo(r, r);
}

// (protected) r = this^2, r != this (HAC 14.16)

function bnpSquareTo(r) {
    var x = this.abs();
    var i = r.t = 2 * x.t;
    while (--i >= 0) r[i] = 0;
    for (i = 0; i < x.t - 1; ++i) {
        var c = x.am(i, x[i], r, 2 * i, 0, 1);
        if ((r[i + x.t] += x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >= x.DV) {
            r[i + x.t] -= x.DV;
            r[i + x.t + 1] = 1;
        }
    }
    if (r.t > 0) r[r.t - 1] += x.am(i, x[i], r, 2 * i, 0, 1);
    r.s = 0;
    r.clamp();
}

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.

function bnpDivRemTo(m, q, r) {
    var pm = m.abs();
    if (pm.t <= 0) return;
    var pt = this.abs();
    if (pt.t < pm.t) {
        if (q != null) q.fromInt(0);
        if (r != null) this.copyTo(r);
        return;
    }
    if (r == null) r = nbi();
    var y = nbi(),
        ts = this.s,
        ms = m.s;
    var nsh = this.DB - nbits(pm[pm.t - 1]); // normalize modulus
    if (nsh > 0) {
        pm.lShiftTo(nsh, y);
        pt.lShiftTo(nsh, r);
    }
    else {
        pm.copyTo(y);
        pt.copyTo(r);
    }
    var ys = y.t;
    var y0 = y[ys - 1];
    if (y0 == 0) return;
    var yt = y0 * (1 << this.F1) + ((ys > 1) ? y[ys - 2] >> this.F2 : 0);
    var d1 = this.FV / yt,
        d2 = (1 << this.F1) / yt,
        e = 1 << this.F2;
    var i = r.t,
        j = i - ys,
        t = (q == null) ? nbi() : q;
    y.dlShiftTo(j, t);
    if (r.compareTo(t) >= 0) {
        r[r.t++] = 1;
        r.subTo(t, r);
    }
    BigInteger.ONE.dlShiftTo(ys, t);
    t.subTo(y, y); // "negative" y so we can replace sub with am later
    while (y.t < ys) y[y.t++] = 0;
    while (--j >= 0) {
        // Estimate quotient digit
        var qd = (r[--i] == y0) ? this.DM : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2);
        if ((r[i] += y.am(0, qd, r, j, 0, ys)) < qd) { // Try it out
            y.dlShiftTo(j, t);
            r.subTo(t, r);
            while (r[i] < --qd) r.subTo(t, r);
        }
    }
    if (q != null) {
        r.drShiftTo(ys, q);
        if (ts != ms) BigInteger.ZERO.subTo(q, q);
    }
    r.t = ys;
    r.clamp();
    if (nsh > 0) r.rShiftTo(nsh, r); // Denormalize remainder
    if (ts < 0) BigInteger.ZERO.subTo(r, r);
}

// (public) this mod a

function bnMod(a) {
    var r = nbi();
    this.abs().divRemTo(a, null, r);
    if (this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r, r);
    return r;
}

// Modular reduction using "classic" algorithm

function Classic(m) {
    this.m = m;
}

function cConvert(x) {
    if (x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
    else return x;
}

function cRevert(x) {
    return x;
}

function cReduce(x) {
    x.divRemTo(this.m, null, x);
}

function cMulTo(x, y, r) {
    x.multiplyTo(y, r);
    this.reduce(r);
}

function cSqrTo(x, r) {
    x.squareTo(r);
    this.reduce(r);
}

Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.

function bnpInvDigit() {
    if (this.t < 1) return 0;
    var x = this[0];
    if ((x & 1) == 0) return 0;
    var y = x & 3; // y == 1/x mod 2^2
    y = (y * (2 - (x & 0xf) * y)) & 0xf; // y == 1/x mod 2^4
    y = (y * (2 - (x & 0xff) * y)) & 0xff; // y == 1/x mod 2^8
    y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff; // y == 1/x mod 2^16
    // last step - calculate inverse mod DV directly;
    // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
    y = (y * (2 - x * y % this.DV)) % this.DV; // y == 1/x mod 2^dbits
    // we really want the negative inverse, and -DV < y < DV
    return (y > 0) ? this.DV - y : -y;
}

// Montgomery reduction

function Montgomery(m) {
    this.m = m;
    this.mp = m.invDigit();
    this.mpl = this.mp & 0x7fff;
    this.mph = this.mp >> 15;
    this.um = (1 << (m.DB - 15)) - 1;
    this.mt2 = 2 * m.t;
}

// xR mod m

function montConvert(x) {
    var r = nbi();
    x.abs().dlShiftTo(this.m.t, r);
    r.divRemTo(this.m, null, r);
    if (x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r, r);
    return r;
}

// x/R mod m

function montRevert(x) {
    var r = nbi();
    x.copyTo(r);
    this.reduce(r);
    return r;
}

// x = x/R mod m (HAC 14.32)

function montReduce(x) {
    while (x.t <= this.mt2) // pad x so am has enough room later
        x[x.t++] = 0;
    for (var i = 0; i < this.m.t; ++i) {
        // faster way of calculating u0 = x[i]*mp mod DV
        var j = x[i] & 0x7fff;
        var u0 = (j * this.mpl + (((j * this.mph + (x[i] >> 15) * this.mpl) & this.um) << 15)) & x.DM;
        // use am to combine the multiply-shift-add into one call
        j = i + this.m.t;
        x[j] += this.m.am(0, u0, x, i, 0, this.m.t);
        // propagate carry
        while (x[j] >= x.DV) {
            x[j] -= x.DV;
            x[++j]++;
        }
    }
    x.clamp();
    x.drShiftTo(this.m.t, x);
    if (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
}

// r = "x^2/R mod m"; x != r

function montSqrTo(x, r) {
    x.squareTo(r);
    this.reduce(r);
}

// r = "xy/R mod m"; x,y != r

function montMulTo(x, y, r) {
    x.multiplyTo(y, r);
    this.reduce(r);
}

Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;

// (protected) true iff this is even

function bnpIsEven() {
    return ((this.t > 0) ? (this[0] & 1) : this.s) == 0;
}

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)

function bnpExp(e, z) {
    if (e > 0xffffffff || e < 1) return BigInteger.ONE;
    var r = nbi(),
        r2 = nbi(),
        g = z.convert(this),
        i = nbits(e) - 1;
    g.copyTo(r);
    while (--i >= 0) {
        z.sqrTo(r, r2);
        if ((e & (1 << i)) > 0) z.mulTo(r2, g, r);
        else {
            var t = r;
            r = r2;
            r2 = t;
        }
    }
    return z.revert(r);
}

// (public) this^e % m, 0 <= e < 2^32

function bnModPowInt(e, m) {
    var z;
    if (e < 256 || m.isEven()) z = new Classic(m);
    else z = new Montgomery(m);
    return this.exp(e, z);
}

// protected
BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;

// public
BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;

// "constants"
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);


function bnClone() {
    var r = nbi();
    this.copyTo(r);
    return r;
}

// (public) return value as integer

function bnIntValue() {
    if (this.s < 0) {
        if (this.t == 1) return this[0] - this.DV;
        else if (this.t == 0) return -1;
    }
    else if (this.t == 1) return this[0];
    else if (this.t == 0) return 0;
    // assumes 16 < DB < 32
    return ((this[1] & ((1 << (32 - this.DB)) - 1)) << this.DB) | this[0];
}

// (public) return value as byte

function bnByteValue() {
    return (this.t == 0) ? this.s : (this[0] << 24) >> 24;
}

// (public) return value as short (assumes DB>=16)

function bnShortValue() {
    return (this.t == 0) ? this.s : (this[0] << 16) >> 16;
}

// (protected) return x s.t. r^x < DV

function bnpChunkSize(r) {
    return Math.floor(Math.LN2 * this.DB / Math.log(r));
}

// (public) 0 if this == 0, 1 if this > 0

function bnSigNum() {
    if (this.s < 0) return -1;
    else if (this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
    else return 1;
}

// (protected) convert to radix string

function bnpToRadix(b) {
    if (b == null) b = 10;
    if (this.signum() == 0 || b < 2 || b > 36) return "0";
    var cs = this.chunkSize(b);
    var a = Math.pow(b, cs);
    var d = nbv(a),
        y = nbi(),
        z = nbi(),
        r = "";
    this.divRemTo(d, y, z);
    while (y.signum() > 0) {
        r = (a + z.intValue()).toString(b).substr(1) + r;
        y.divRemTo(d, y, z);
    }
    return z.intValue().toString(b) + r;
}

// (protected) convert from radix string

function bnpFromRadix(s, b) {
    this.fromInt(0);
    if (b == null) b = 10;
    var cs = this.chunkSize(b);
    var d = Math.pow(b, cs),
        mi = false,
        j = 0,
        w = 0;
    for (var i = 0; i < s.length; ++i) {
        var x = intAt(s, i);
        if (x < 0) {
            if (s.charAt(i) == "-" && this.signum() == 0) mi = true;
            continue;
        }
        w = b * w + x;
        if (++j >= cs) {
            this.dMultiply(d);
            this.dAddOffset(w, 0);
            j = 0;
            w = 0;
        }
    }
    if (j > 0) {
        this.dMultiply(Math.pow(b, j));
        this.dAddOffset(w, 0);
    }
    if (mi) BigInteger.ZERO.subTo(this, this);
}

// (protected) alternate constructor

function bnpFromNumber(a, b, c) {
    if ("number" == typeof b) {
        // new BigInteger(int,int,RNG)
        if (a < 2) this.fromInt(1);
        else {
            this.fromNumber(a, c);
            if (!this.testBit(a - 1)) // force MSB set
                this.bitwiseTo(BigInteger.ONE.shiftLeft(a - 1), op_or, this);
            if (this.isEven()) this.dAddOffset(1, 0); // force odd
            while (!this.isProbablePrime(b)) {
                this.dAddOffset(2, 0);
                if (this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a - 1), this);
            }
        }
    }
    else {
        // new BigInteger(int,RNG)
        var x = new Array(),
            t = a & 7;
        x.length = (a >> 3) + 1;
        b.nextBytes(x);
        if (t > 0) x[0] &= ((1 << t) - 1);
        else x[0] = 0;
        this.fromString(x, 256);
    }
}

// (public) convert to bigendian byte array

function bnToByteArray() {
    var i = this.t,
        r = new Array();
    r[0] = this.s;
    var p = this.DB - (i * this.DB) % 8,
        d, k = 0;
    if (i-- > 0) {
        if (p < this.DB && (d = this[i] >> p) != (this.s & this.DM) >> p) r[k++] = d | (this.s << (this.DB - p));
        while (i >= 0) {
            if (p < 8) {
                d = (this[i] & ((1 << p) - 1)) << (8 - p);
                d |= this[--i] >> (p += this.DB - 8);
            }
            else {
                d = (this[i] >> (p -= 8)) & 0xff;
                if (p <= 0) {
                    p += this.DB;
                    --i;
                }
            }
            if ((d & 0x80) != 0) d |= -256;
            if (k == 0 && (this.s & 0x80) != (d & 0x80))++k;
            if (k > 0 || d != this.s) r[k++] = d;
        }
    }
    return r;
}

function bnEquals(a) {
    return (this.compareTo(a) == 0);
}

function bnMin(a) {
    return (this.compareTo(a) < 0) ? this : a;
}

function bnMax(a) {
    return (this.compareTo(a) > 0) ? this : a;
}

// (protected) r = this op a (bitwise)

function bnpBitwiseTo(a, op, r) {
    var i, f, m = Math.min(a.t, this.t);
    for (i = 0; i < m; ++i) r[i] = op(this[i], a[i]);
    if (a.t < this.t) {
        f = a.s & this.DM;
        for (i = m; i < this.t; ++i) r[i] = op(this[i], f);
        r.t = this.t;
    }
    else {
        f = this.s & this.DM;
        for (i = m; i < a.t; ++i) r[i] = op(f, a[i]);
        r.t = a.t;
    }
    r.s = op(this.s, a.s);
    r.clamp();
}

// (public) this & a

function op_and(x, y) {
    return x & y;
}

function bnAnd(a) {
    var r = nbi();
    this.bitwiseTo(a, op_and, r);
    return r;
}

// (public) this | a

function op_or(x, y) {
    return x | y;
}

function bnOr(a) {
    var r = nbi();
    this.bitwiseTo(a, op_or, r);
    return r;
}

// (public) this ^ a

function op_xor(x, y) {
    return x ^ y;
}

function bnXor(a) {
    var r = nbi();
    this.bitwiseTo(a, op_xor, r);
    return r;
}

// (public) this & ~a

function op_andnot(x, y) {
    return x & ~y;
}

function bnAndNot(a) {
    var r = nbi();
    this.bitwiseTo(a, op_andnot, r);
    return r;
}

// (public) ~this

function bnNot() {
    var r = nbi();
    for (var i = 0; i < this.t; ++i) r[i] = this.DM & ~this[i];
    r.t = this.t;
    r.s = ~this.s;
    return r;
}

// (public) this << n

function bnShiftLeft(n) {
    var r = nbi();
    if (n < 0) this.rShiftTo(-n, r);
    else this.lShiftTo(n, r);
    return r;
}

// (public) this >> n

function bnShiftRight(n) {
    var r = nbi();
    if (n < 0) this.lShiftTo(-n, r);
    else this.rShiftTo(n, r);
    return r;
}

// return index of lowest 1-bit in x, x < 2^31

function lbit(x) {
    if (x == 0) return -1;
    var r = 0;
    if ((x & 0xffff) == 0) {
        x >>= 16;
        r += 16;
    }
    if ((x & 0xff) == 0) {
        x >>= 8;
        r += 8;
    }
    if ((x & 0xf) == 0) {
        x >>= 4;
        r += 4;
    }
    if ((x & 3) == 0) {
        x >>= 2;
        r += 2;
    }
    if ((x & 1) == 0)++r;
    return r;
}

// (public) returns index of lowest 1-bit (or -1 if none)

function bnGetLowestSetBit() {
    for (var i = 0; i < this.t; ++i)
        if (this[i] != 0) return i * this.DB + lbit(this[i]);
    if (this.s < 0) return this.t * this.DB;
    return -1;
}

// return number of 1 bits in x

function cbit(x) {
    var r = 0;
    while (x != 0) {
        x &= x - 1;
        ++r;
    }
    return r;
}

// (public) return number of set bits

function bnBitCount() {
    var r = 0,
        x = this.s & this.DM;
    for (var i = 0; i < this.t; ++i) r += cbit(this[i] ^ x);
    return r;
}

// (public) true iff nth bit is set

function bnTestBit(n) {
    var j = Math.floor(n / this.DB);
    if (j >= this.t) return (this.s != 0);
    return ((this[j] & (1 << (n % this.DB))) != 0);
}

// (protected) this op (1<<n)

function bnpChangeBit(n, op) {
    var r = BigInteger.ONE.shiftLeft(n);
    this.bitwiseTo(r, op, r);
    return r;
}

// (public) this | (1<<n)

function bnSetBit(n) {
    return this.changeBit(n, op_or);
}

// (public) this & ~(1<<n)

function bnClearBit(n) {
    return this.changeBit(n, op_andnot);
}

// (public) this ^ (1<<n)

function bnFlipBit(n) {
    return this.changeBit(n, op_xor);
}

// (protected) r = this + a

function bnpAddTo(a, r) {
    var i = 0,
        c = 0,
        m = Math.min(a.t, this.t);
    while (i < m) {
        c += this[i] + a[i];
        r[i++] = c & this.DM;
        c >>= this.DB;
    }
    if (a.t < this.t) {
        c += a.s;
        while (i < this.t) {
            c += this[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        c += this.s;
    }
    else {
        c += this.s;
        while (i < a.t) {
            c += a[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        c += a.s;
    }
    r.s = (c < 0) ? -1 : 0;
    if (c > 0) r[i++] = c;
    else if (c < -1) r[i++] = this.DV + c;
    r.t = i;
    r.clamp();
}

// (public) this + a

function bnAdd(a) {
    var r = nbi();
    this.addTo(a, r);
    return r;
}

// (public) this - a

function bnSubtract(a) {
    var r = nbi();
    this.subTo(a, r);
    return r;
}

// (public) this * a

function bnMultiply(a) {
    var r = nbi();
    this.multiplyTo(a, r);
    return r;
}

// (public) this^2

function bnSquare() {
    var r = nbi();
    this.squareTo(r);
    return r;
}

// (public) this / a

function bnDivide(a) {
    var r = nbi();
    this.divRemTo(a, r, null);
    return r;
}

// (public) this % a

function bnRemainder(a) {
    var r = nbi();
    this.divRemTo(a, null, r);
    return r;
}

// (public) [this/a,this%a]

function bnDivideAndRemainder(a) {
    var q = nbi(),
        r = nbi();
    this.divRemTo(a, q, r);
    return new Array(q, r);
}

// (protected) this *= n, this >= 0, 1 < n < DV

function bnpDMultiply(n) {
    this[this.t] = this.am(0, n - 1, this, 0, 0, this.t);
    ++this.t;
    this.clamp();
}

// (protected) this += n << w words, this >= 0

function bnpDAddOffset(n, w) {
    if (n == 0) return;
    while (this.t <= w) this[this.t++] = 0;
    this[w] += n;
    while (this[w] >= this.DV) {
        this[w] -= this.DV;
        if (++w >= this.t) this[this.t++] = 0;
        ++this[w];
    }
}

// A "null" reducer

function NullExp() {}

function nNop(x) {
    return x;
}

function nMulTo(x, y, r) {
    x.multiplyTo(y, r);
}

function nSqrTo(x, r) {
    x.squareTo(r);
}

NullExp.prototype.convert = nNop;
NullExp.prototype.revert = nNop;
NullExp.prototype.mulTo = nMulTo;
NullExp.prototype.sqrTo = nSqrTo;

// (public) this^e

function bnPow(e) {
    return this.exp(e, new NullExp());
}

// (protected) r = lower n words of "this * a", a.t <= n
// "this" should be the larger one if appropriate.

function bnpMultiplyLowerTo(a, n, r) {
    var i = Math.min(this.t + a.t, n);
    r.s = 0; // assumes a,this >= 0
    r.t = i;
    while (i > 0) r[--i] = 0;
    var j;
    for (j = r.t - this.t; i < j; ++i) r[i + this.t] = this.am(0, a[i], r, i, 0, this.t);
    for (j = Math.min(a.t, n); i < j; ++i) this.am(0, a[i], r, i, 0, n - i);
    r.clamp();
}

// (protected) r = "this * a" without lower n words, n > 0
// "this" should be the larger one if appropriate.

function bnpMultiplyUpperTo(a, n, r) {
    --n;
    var i = r.t = this.t + a.t - n;
    r.s = 0; // assumes a,this >= 0
    while (--i >= 0) r[i] = 0;
    for (i = Math.max(n - this.t, 0); i < a.t; ++i)
        r[this.t + i - n] = this.am(n - i, a[i], r, 0, 0, this.t + i - n);
    r.clamp();
    r.drShiftTo(1, r);
}

// Barrett modular reduction

function Barrett(m) {
    // setup Barrett
    this.r2 = nbi();
    this.q3 = nbi();
    BigInteger.ONE.dlShiftTo(2 * m.t, this.r2);
    this.mu = this.r2.divide(m);
    this.m = m;
}

function barrettConvert(x) {
    if (x.s < 0 || x.t > 2 * this.m.t) return x.mod(this.m);
    else if (x.compareTo(this.m) < 0) return x;
    else {
        var r = nbi();
        x.copyTo(r);
        this.reduce(r);
        return r;
    }
}

function barrettRevert(x) {
    return x;
}

// x = x mod m (HAC 14.42)

function barrettReduce(x) {
    x.drShiftTo(this.m.t - 1, this.r2);
    if (x.t > this.m.t + 1) {
        x.t = this.m.t + 1;
        x.clamp();
    }
    this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3);
    this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2);
    while (x.compareTo(this.r2) < 0) x.dAddOffset(1, this.m.t + 1);
    x.subTo(this.r2, x);
    while (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
}

// r = x^2 mod m; x != r

function barrettSqrTo(x, r) {
    x.squareTo(r);
    this.reduce(r);
}

// r = x*y mod m; x,y != r

function barrettMulTo(x, y, r) {
    x.multiplyTo(y, r);
    this.reduce(r);
}

Barrett.prototype.convert = barrettConvert;
Barrett.prototype.revert = barrettRevert;
Barrett.prototype.reduce = barrettReduce;
Barrett.prototype.mulTo = barrettMulTo;
Barrett.prototype.sqrTo = barrettSqrTo;

// (public) this^e % m (HAC 14.85)

function bnModPow(e, m) {
    var i = e.bitLength(),
        k, r = nbv(1),
        z;
    if (i <= 0) return r;
    else if (i < 18) k = 1;
    else if (i < 48) k = 3;
    else if (i < 144) k = 4;
    else if (i < 768) k = 5;
    else k = 6;
    if (i < 8) z = new Classic(m);
    else if (m.isEven()) z = new Barrett(m);
    else z = new Montgomery(m);

    // precomputation
    var g = new Array(),
        n = 3,
        k1 = k - 1,
        km = (1 << k) - 1;
    g[1] = z.convert(this);
    if (k > 1) {
        var g2 = nbi();
        z.sqrTo(g[1], g2);
        while (n <= km) {
            g[n] = nbi();
            z.mulTo(g2, g[n - 2], g[n]);
            n += 2;
        }
    }

    var j = e.t - 1,
        w, is1 = true,
        r2 = nbi(),
        t;
    i = nbits(e[j]) - 1;
    while (j >= 0) {
        if (i >= k1) w = (e[j] >> (i - k1)) & km;
        else {
            w = (e[j] & ((1 << (i + 1)) - 1)) << (k1 - i);
            if (j > 0) w |= e[j - 1] >> (this.DB + i - k1);
        }

        n = k;
        while ((w & 1) == 0) {
            w >>= 1;
            --n;
        }
        if ((i -= n) < 0) {
            i += this.DB;
            --j;
        }
        if (is1) { // ret == 1, don't bother squaring or multiplying it
            g[w].copyTo(r);
            is1 = false;
        }
        else {
            while (n > 1) {
                z.sqrTo(r, r2);
                z.sqrTo(r2, r);
                n -= 2;
            }
            if (n > 0) z.sqrTo(r, r2);
            else {
                t = r;
                r = r2;
                r2 = t;
            }
            z.mulTo(r2, g[w], r);
        }

        while (j >= 0 && (e[j] & (1 << i)) == 0) {
            z.sqrTo(r, r2);
            t = r;
            r = r2;
            r2 = t;
            if (--i < 0) {
                i = this.DB - 1;
                --j;
            }
        }
    }
    return z.revert(r);
}

// (public) gcd(this,a) (HAC 14.54)

function bnGCD(a) {
    var x = (this.s < 0) ? this.negate() : this.clone();
    var y = (a.s < 0) ? a.negate() : a.clone();
    if (x.compareTo(y) < 0) {
        var t = x;
        x = y;
        y = t;
    }
    var i = x.getLowestSetBit(),
        g = y.getLowestSetBit();
    if (g < 0) return x;
    if (i < g) g = i;
    if (g > 0) {
        x.rShiftTo(g, x);
        y.rShiftTo(g, y);
    }
    while (x.signum() > 0) {
        if ((i = x.getLowestSetBit()) > 0) x.rShiftTo(i, x);
        if ((i = y.getLowestSetBit()) > 0) y.rShiftTo(i, y);
        if (x.compareTo(y) >= 0) {
            x.subTo(y, x);
            x.rShiftTo(1, x);
        }
        else {
            y.subTo(x, y);
            y.rShiftTo(1, y);
        }
    }
    if (g > 0) y.lShiftTo(g, y);
    return y;
}

// (protected) this % n, n < 2^26

function bnpModInt(n) {
    if (n <= 0) return 0;
    var d = this.DV % n,
        r = (this.s < 0) ? n - 1 : 0;
    if (this.t > 0) if (d == 0) r = this[0] % n;
    else for (var i = this.t - 1; i >= 0; --i) r = (d * r + this[i]) % n;
    return r;
}

// (public) 1/this % m (HAC 14.61)

function bnModInverse(m) {
    var ac = m.isEven();
    if ((this.isEven() && ac) || m.signum() == 0) return BigInteger.ZERO;
    var u = m.clone(),
        v = this.clone();
    var a = nbv(1),
        b = nbv(0),
        c = nbv(0),
        d = nbv(1);
    while (u.signum() != 0) {
        while (u.isEven()) {
            u.rShiftTo(1, u);
            if (ac) {
                if (!a.isEven() || !b.isEven()) {
                    a.addTo(this, a);
                    b.subTo(m, b);
                }
                a.rShiftTo(1, a);
            }
            else if (!b.isEven()) b.subTo(m, b);
            b.rShiftTo(1, b);
        }
        while (v.isEven()) {
            v.rShiftTo(1, v);
            if (ac) {
                if (!c.isEven() || !d.isEven()) {
                    c.addTo(this, c);
                    d.subTo(m, d);
                }
                c.rShiftTo(1, c);
            }
            else if (!d.isEven()) d.subTo(m, d);
            d.rShiftTo(1, d);
        }
        if (u.compareTo(v) >= 0) {
            u.subTo(v, u);
            if (ac) a.subTo(c, a);
            b.subTo(d, b);
        }
        else {
            v.subTo(u, v);
            if (ac) c.subTo(a, c);
            d.subTo(b, d);
        }
    }
    if (v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
    if (d.compareTo(m) >= 0) return d.subtract(m);
    if (d.signum() < 0) d.addTo(m, d);
    else return d;
    if (d.signum() < 0) return d.add(m);
    else return d;
}

var lowprimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997];
var lplim = (1 << 26) / lowprimes[lowprimes.length - 1];

// (public) test primality with certainty >= 1-.5^t

function bnIsProbablePrime(t) {
    var i, x = this.abs();
    if (x.t == 1 && x[0] <= lowprimes[lowprimes.length - 1]) {
        for (i = 0; i < lowprimes.length; ++i)
            if (x[0] == lowprimes[i]) return true;
        return false;
    }
    if (x.isEven()) return false;
    i = 1;
    while (i < lowprimes.length) {
        var m = lowprimes[i],
            j = i + 1;
        while (j < lowprimes.length && m < lplim) m *= lowprimes[j++];
        m = x.modInt(m);
        while (i < j) if (m % lowprimes[i++] == 0) return false;
    }
    return x.millerRabin(t);
}

// (protected) true if probably prime (HAC 4.24, Miller-Rabin)

function bnpMillerRabin(t) {
    var n1 = this.subtract(BigInteger.ONE);
    var k = n1.getLowestSetBit();
    if (k <= 0) return false;
    var r = n1.shiftRight(k);
    t = (t + 1) >> 1;
    if (t > lowprimes.length) t = lowprimes.length;
    var a = nbi();
    for (var i = 0; i < t; ++i) {
        //Pick bases at random, instead of starting at 2
        a.fromInt(lowprimes[Math.floor(Math.random() * lowprimes.length)]);
        var y = a.modPow(r, this);
        if (y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
            var j = 1;
            while (j++ < k && y.compareTo(n1) != 0) {
                y = y.modPowInt(2, this);
                if (y.compareTo(BigInteger.ONE) == 0) return false;
            }
            if (y.compareTo(n1) != 0) return false;
        }
    }
    return true;
}

// protected
BigInteger.prototype.chunkSize = bnpChunkSize;
BigInteger.prototype.toRadix = bnpToRadix;
BigInteger.prototype.fromRadix = bnpFromRadix;
BigInteger.prototype.fromNumber = bnpFromNumber;
BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
BigInteger.prototype.changeBit = bnpChangeBit;
BigInteger.prototype.addTo = bnpAddTo;
BigInteger.prototype.dMultiply = bnpDMultiply;
BigInteger.prototype.dAddOffset = bnpDAddOffset;
BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
BigInteger.prototype.modInt = bnpModInt;
BigInteger.prototype.millerRabin = bnpMillerRabin;

// public
BigInteger.prototype.clone = bnClone;
BigInteger.prototype.intValue = bnIntValue;
BigInteger.prototype.byteValue = bnByteValue;
BigInteger.prototype.shortValue = bnShortValue;
BigInteger.prototype.signum = bnSigNum;
BigInteger.prototype.toByteArray = bnToByteArray;
BigInteger.prototype.equals = bnEquals;
BigInteger.prototype.min = bnMin;
BigInteger.prototype.max = bnMax;
BigInteger.prototype.and = bnAnd;
BigInteger.prototype.or = bnOr;
BigInteger.prototype.xor = bnXor;
BigInteger.prototype.andNot = bnAndNot;
BigInteger.prototype.not = bnNot;
BigInteger.prototype.shiftLeft = bnShiftLeft;
BigInteger.prototype.shiftRight = bnShiftRight;
BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
BigInteger.prototype.bitCount = bnBitCount;
BigInteger.prototype.testBit = bnTestBit;
BigInteger.prototype.setBit = bnSetBit;
BigInteger.prototype.clearBit = bnClearBit;
BigInteger.prototype.flipBit = bnFlipBit;
BigInteger.prototype.add = bnAdd;
BigInteger.prototype.subtract = bnSubtract;
BigInteger.prototype.multiply = bnMultiply;
BigInteger.prototype.divide = bnDivide;
BigInteger.prototype.remainder = bnRemainder;
BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
BigInteger.prototype.modPow = bnModPow;
BigInteger.prototype.modInverse = bnModInverse;
BigInteger.prototype.pow = bnPow;
BigInteger.prototype.gcd = bnGCD;
BigInteger.prototype.isProbablePrime = bnIsProbablePrime;

// JSBN-specific extension
BigInteger.prototype.square = bnSquare;// seedrandom.js version 2.0.
// Author: David Bau 4/2/2011
//
// Defines a method Math.seedrandom() that, when called, substitutes
// an explicitly seeded RC4-based algorithm for Math.random().  Also
// supports automatic seeding from local or network sources of entropy.
//
// Usage:
//
//   <script src=http://davidbau.com/encode/seedrandom-min.js></script>
//
//   Math.seedrandom('yipee'); Sets Math.random to a function that is
//                             initialized using the given explicit seed.
//
//   Math.seedrandom();        Sets Math.random to a function that is
//                             seeded using the current time, dom state,
//                             and other accumulated local entropy.
//                             The generated seed string is returned.
//
//   Math.seedrandom('yowza', true);
//                             Seeds using the given explicit seed mixed
//                             together with accumulated entropy.
//
//   <script src="http://bit.ly/srandom-512"></script>
//                             Seeds using physical random bits downloaded
//                             from random.org.
//
//   <script src="https://jsonlib.appspot.com/urandom?callback=Math.seedrandom">
//   </script>                 Seeds using urandom bits from call.jsonlib.com,
//                             which is faster than random.org.
//
// Examples:
//
//   Math.seedrandom("hello");            // Use "hello" as the seed.
//   document.write(Math.random());       // Always 0.5463663768140734
//   document.write(Math.random());       // Always 0.43973793770592234
//   var rng1 = Math.random;              // Remember the current prng.
//
//   var autoseed = Math.seedrandom();    // New prng with an automatic seed.
//   document.write(Math.random());       // Pretty much unpredictable.
//
//   Math.random = rng1;                  // Continue "hello" prng sequence.
//   document.write(Math.random());       // Always 0.554769432473455
//
//   Math.seedrandom(autoseed);           // Restart at the previous seed.
//   document.write(Math.random());       // Repeat the 'unpredictable' value.
//
// Notes:
//
// Each time seedrandom('arg') is called, entropy from the passed seed
// is accumulated in a pool to help generate future seeds for the
// zero-argument form of Math.seedrandom, so entropy can be injected over
// time by calling seedrandom with explicit data repeatedly.
//
// On speed - This javascript implementation of Math.random() is about
// 3-10x slower than the built-in Math.random() because it is not native
// code, but this is typically fast enough anyway.  Seeding is more expensive,
// especially if you use auto-seeding.  Some details (timings on Chrome 4):
//
// Our Math.random()            - avg less than 0.002 milliseconds per call
// seedrandom('explicit')       - avg less than 0.5 milliseconds per call
// seedrandom('explicit', true) - avg less than 2 milliseconds per call
// seedrandom()                 - avg about 38 milliseconds per call
//
// LICENSE (BSD):
//
// Copyright 2010 David Bau, all rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//   1. Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//   2. Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in the
//      documentation and/or other materials provided with the distribution.
//
//   3. Neither the name of this module nor the names of its contributors may
//      be used to endorse or promote products derived from this software
//      without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
/**
 * All code is in an anonymous closure to keep the global namespace clean.
 *
 * @param {number=} overflow
 * @param {number=} startdenom
 */
(function (pool, math, width, chunks, significance, overflow, startdenom)
{


    //
    // seedrandom()
    // This is the seedrandom function described above.
    //
    math['seedrandom'] = function seedrandom(seed, use_entropy)
    {
        var key = [];
        var arc4;

        // Flatten the seed string or build one from local entropy if needed.
        seed = mixkey(flatten(
            use_entropy ? [seed, pool] : arguments.length ? seed : [new Date().getTime(), pool], 3), key);

        // Use the seed to initialize an ARC4 generator.
        arc4 = new ARC4(key);

        // Mix the randomness into accumulated entropy.
        mixkey(arc4.S, pool);

        // Override Math.random
        // This function returns a random double in [0, 1) that contains
        // randomness in every bit of the mantissa of the IEEE 754 value.
        math['random'] = function random()
        { // Closure to return a random double:
            var n = arc4.g(chunks); // Start with a numerator n < 2 ^ 48
            var d = startdenom; //   and denominator d = 2 ^ 48.
            var x = 0; //   and no 'extra last byte'.
            while (n < significance)
            { // Fill up all significant digits by
                n = (n + x) * width; //   shifting numerator and
                d *= width; //   denominator and generating a
                x = arc4.g(1); //   new least-significant-byte.
            }
            while (n >= overflow)
            { // To avoid rounding up, before adding
                n /= 2; //   last byte, shift everything
                d /= 2; //   right using integer math until
                x >>>= 1; //   we have exactly the desired bits.
            }
            return (n + x) / d; // Form the number within [0, 1).
        };

        // Return the seed that was used
        return seed;
    };

    //
    // ARC4
    //
    // An ARC4 implementation.  The constructor takes a key in the form of
    // an array of at most (width) integers that should be 0 <= x < (width).
    //
    // The g(count) method returns a pseudorandom integer that concatenates
    // the next (count) outputs from ARC4.  Its return value is a number x
    // that is in the range 0 <= x < (width ^ count).
    //
    /** @constructor */

    function ARC4(key)
    {
        var t, u, me = this,
            keylen = key.length;
        var i = 0,
            j = me.i = me.j = me.m = 0;
        me.S = [];
        me.c = [];

        // The empty key [] is treated as [0].
        if (!keylen)
        {
            key = [keylen++];
        }

        // Set up S using the standard key scheduling algorithm.
        while (i < width)
        {
            me.S[i] = i++;
        }
        for (i = 0; i < width; i++)
        {
            t = me.S[i];
            j = lowbits(j + t + key[i % keylen]);
            u = me.S[j];
            me.S[i] = u;
            me.S[j] = t;
        }

        // The "g" method returns the next (count) outputs as one number.
        me.g = function getnext(count)
        {
            var s = me.S;
            var i = lowbits(me.i + 1);
            var t = s[i];
            var j = lowbits(me.j + t);
            var u = s[j];
            s[i] = u;
            s[j] = t;
            var r = s[lowbits(t + u)];
            while (--count)
            {
                i = lowbits(i + 1);
                t = s[i];
                j = lowbits(j + t);
                u = s[j];
                s[i] = u;
                s[j] = t;
                r = r * width + s[lowbits(t + u)];
            }
            me.i = i;
            me.j = j;
            return r;
        };
        // For robust unpredictability discard an initial batch of values.
        // See http://www.rsa.com/rsalabs/node.asp?id=2009
        me.g(width);
    }

    //
    // flatten()
    // Converts an object tree to nested arrays of strings.
    //
    /** @param {Object=} result
     * @param {string=} prop
     * @param {string=} typ */

    function flatten(obj, depth, result, prop, typ)
    {
        result = [];
        typ = typeof (obj);
        if (depth && typ == 'object')
        {
            for (prop in obj)
            {
                if (prop.indexOf('S') < 5)
                { // Avoid FF3 bug (local/sessionStorage)
                    try
                    {
                        result.push(flatten(obj[prop], depth - 1));
                    }
                    catch (e)
                    {}
                }
            }
        }
        return (result.length ? result : obj + (typ != 'string' ? '\0' : ''));
    }

    //
    // mixkey()
    // Mixes a string seed into a key that is an array of integers, and
    // returns a shortened string seed that is equivalent to the result key.
    //
    /** @param {number=} smear
     * @param {number=} j */

    function mixkey(seed, key, smear, j)
    {
        seed += ''; // Ensure the seed is a string
        smear = 0;
        for (j = 0; j < seed.length; j++)
        {
            key[lowbits(j)] = lowbits((smear ^= key[lowbits(j)] * 19) + seed.charCodeAt(j));
        }
        seed = '';
        for (j in key)
        {
            seed += String.fromCharCode(key[j]);
        }
        return seed;
    }

    //
    // lowbits()
    // A quick "n mod width" for width a power of 2.
    //


    function lowbits(n)
    {
        return n & (width - 1);
    }

    //
    // The following constants are related to IEEE 754 limits.
    //
    startdenom = math.pow(width, chunks);
    significance = math.pow(2, significance);
    overflow = significance * 2;

    //
    // When seedrandom.js is loaded, we immediately mix a few bits
    // from the built-in RNG into the entropy pool.  Because we do
    // not want to intefere with determinstic PRNG state later,
    // seedrandom will not call math.random on its own again after
    // initialization.
    //
    mixkey(math.random(), pool);

    // End anonymous scope, and pass initial values.
})([], // pool: entropy pool starts empty
    Math, // math: package containing random, pow, and seedrandom
    256, // width: each RC4 output is 0 <= x < 256
    6, // chunks: at least six RC4 outputs for each double
    52 // significance: there are 52 significant digits in a double
);


// This is not really a random number generator object, and two SeededRandom
// objects will conflict with one another, but it's good enough for generating
// the rsa key.
function SeededRandom(){}

function SRnextBytes(ba)
{
    var i;
    for(i = 0; i < ba.length; i++)
    {
        ba[i] = Math.floor(Math.random() * 256);
    }
}

SeededRandom.prototype.nextBytes = SRnextBytes;

// prng4.js - uses Arcfour as a PRNG

function Arcfour() {
    this.i = 0;
    this.j = 0;
    this.S = new Array();
}

// Initialize arcfour context from key, an array of ints, each from [0..255]
function ARC4init(key) {
    var i, j, t;
    for(i = 0; i < 256; ++i)
        this.S[i] = i;
    j = 0;
    for(i = 0; i < 256; ++i) {
        j = (j + this.S[i] + key[i % key.length]) & 255;
        t = this.S[i];
        this.S[i] = this.S[j];
        this.S[j] = t;
    }
    this.i = 0;
    this.j = 0;
}

function ARC4next() {
    var t;
    this.i = (this.i + 1) & 255;
    this.j = (this.j + this.S[this.i]) & 255;
    t = this.S[this.i];
    this.S[this.i] = this.S[this.j];
    this.S[this.j] = t;
    return this.S[(t + this.S[this.i]) & 255];
}

Arcfour.prototype.init = ARC4init;
Arcfour.prototype.next = ARC4next;

// Plug in your RNG constructor here
function prng_newstate() {
    return new Arcfour();
}

// Pool size must be a multiple of 4 and greater than 32.
// An array of bytes the size of the pool will be passed to init()
var rng_psize = 256;

// Random number generator - requires a PRNG backend, e.g. prng4.js

// For best results, put code like
// <body onClick='rng_seed_time();' onKeyPress='rng_seed_time();'>
// in your main HTML document.

var rng_state;
var rng_pool;
var rng_pptr;

// Mix in a 32-bit integer into the pool
function rng_seed_int(x) {
    rng_pool[rng_pptr++] ^= x & 255;
    rng_pool[rng_pptr++] ^= (x >> 8) & 255;
    rng_pool[rng_pptr++] ^= (x >> 16) & 255;
    rng_pool[rng_pptr++] ^= (x >> 24) & 255;
    if(rng_pptr >= rng_psize) rng_pptr -= rng_psize;
}

// Mix in the current time (w/milliseconds) into the pool
function rng_seed_time() {
    rng_seed_int(new Date().getTime());
}

// Initialize the pool with junk if needed.
if(rng_pool == null) {
    rng_pool = new Array();
    rng_pptr = 0;
    var t;
    while(rng_pptr < rng_psize) {  // extract some randomness from Math.random()
        t = Math.floor(65536 * Math.random());
        rng_pool[rng_pptr++] = t >>> 8;
        rng_pool[rng_pptr++] = t & 255;
    }
    rng_pptr = 0;
    rng_seed_time();
    //rng_seed_int(window.screenX);
    //rng_seed_int(window.screenY);
}

function rng_get_byte() {
    if(rng_state == null) {
        rng_seed_time();
        rng_state = prng_newstate();
        rng_state.init(rng_pool);
        for(rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr)
            rng_pool[rng_pptr] = 0;
        rng_pptr = 0;
        //rng_pool = null;
    }
    // TODO: allow reseeding after first request
    return rng_state.next();
}

function rng_get_bytes(ba) {
    var i;
    for(i = 0; i < ba.length; ++i) ba[i] = rng_get_byte();
}

function SecureRandom() {}

SecureRandom.prototype.nextBytes = rng_get_bytes;/**
 *
 *  Secure Hash Algorithm (SHA256)
 *  http://www.webtoolkit.info/
 *
 *  Original code by Angel Marin, Paul Johnston.
 *
 **/

var crypto = require('crypto');

function SHA256(s){
    return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

var sha256 = {}
sha256.hex = function(s)
{
    return SHA256(s);
}

/**
 *
 *  Secure Hash Algorithm (SHA1)
 *  http://www.webtoolkit.info/
 *
 **/

function SHA1 (msg) {
    return crypto.createHash('sha1').update(msg, 'utf8').digest('hex');
}

var sha1 = {}
sha1.hex = function(s)
{
    return SHA1(s);
}

/**
 *
 *  MD5 (Message-Digest Algorithm)
 *  http://www.webtoolkit.info/
 *
 **/

var MD5 = function (string) {
    return crypto.createHash('md5').update(string, 'utf8').digest('hex');
}// Depends on jsbn.js and rng.js
// Version 1.1: support utf-8 encoding in pkcs1pad2
// convert a (hex) string to a bignum object


function parseBigInt(str, r)
{
    return new BigInteger(str, r);
}

function linebrk(s, n)
{
    var ret = "";
    var i = 0;
    while (i + n < s.length)
    {
        ret += s.substring(i, i + n) + "\n";
        i += n;
    }
    return ret + s.substring(i, s.length);
}

function byte2Hex(b)
{
    if (b < 0x10) return "0" + b.toString(16);
    else return b.toString(16);
}

// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint


function pkcs1pad2(s, n)
{
    if (n < s.length + 11)
    { // TODO: fix for utf-8
        //alert("Message too long for RSA (n=" + n + ", l=" + s.length + ")");
        //return null;
        throw "Message too long for RSA (n=" + n + ", l=" + s.length + ")";
    }
    var ba = new Array();
    var i = s.length - 1;
    while (i >= 0 && n > 0)
    {
        var c = s.charCodeAt(i--);
        if (c < 128)
        { // encode using utf-8
            ba[--n] = c;
        }
        else if ((c > 127) && (c < 2048))
        {
            ba[--n] = (c & 63) | 128;
            ba[--n] = (c >> 6) | 192;
        }
        else
        {
            ba[--n] = (c & 63) | 128;
            ba[--n] = ((c >> 6) & 63) | 128;
            ba[--n] = (c >> 12) | 224;
        }
    }
    ba[--n] = 0;
    var rng = new SecureRandom();
    var x = new Array();
    while (n > 2)
    { // random non-zero pad
        x[0] = 0;
        while (x[0] == 0) rng.nextBytes(x);
        ba[--n] = x[0];
    }
    ba[--n] = 2;
    ba[--n] = 0;
    return new BigInteger(ba);
}

// "empty" RSA key constructor


function RSAKey()
{
    this.n = null;
    this.e = 0;
    this.d = null;
    this.p = null;
    this.q = null;
    this.dmp1 = null;
    this.dmq1 = null;
    this.coeff = null;
}
// Set the public key fields N and e from hex strings


function RSASetPublic(N, E)
{
    if (N != null && E != null && N.length > 0 && E.length > 0)
    {
        this.n = parseBigInt(N, 16);
        this.e = parseInt(E, 16);
    }
    else alert("Invalid RSA public key");
}

// Perform raw public operation on "x": return x^e (mod n)


function RSADoPublic(x)
{
    return x.modPowInt(this.e, this.n);
}

// Return the PKCS#1 RSA encryption of "text" as an even-length hex string


function RSAEncrypt(text)
{
    var m = pkcs1pad2(text, (this.n.bitLength() + 7) >> 3);
    if (m == null) return null;
    var c = this.doPublic(m);
    if (c == null) return null;
    var h = c.toString(16);
    if ((h.length & 1) == 0) return h;
    else return "0" + h;
}

function RSAToJSON()
{
    return {
        coeff: this.coeff.toString(16),
        d: this.d.toString(16),
        dmp1: this.dmp1.toString(16),
        dmq1: this.dmq1.toString(16),
        e: this.e.toString(16),
        n: this.n.toString(16),
        p: this.p.toString(16),
        q: this.q.toString(16),
    }
}

function RSAParse(rsaString) {
    var json = JSON.parse(rsaString);
    var rsa = new RSAKey();

    rsa.setPrivateEx(json.n, json.e, json.d, json.p, json.q, json.dmp1, json.dmq1, json.coeff);

    return rsa;
}

// Return the PKCS#1 RSA encryption of "text" as a Base64-encoded string
//function RSAEncryptB64(text) {
//  var h = this.encrypt(text);
//  if(h) return hex2b64(h); else return null;
//}
// protected
RSAKey.prototype.doPublic = RSADoPublic;

// public
RSAKey.prototype.parseInt = parseBigInt;
RSAKey.prototype.setPublic = RSASetPublic;
RSAKey.prototype.encrypt = RSAEncrypt;
RSAKey.prototype.toJSON = RSAToJSON;
RSAKey.parse = RSAParse;

// Version 1.1: support utf-8 decoding in pkcs1unpad2
// Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext

function pkcs1unpad2(d, n)
{
    var b = d.toByteArray();
    var i = 0;
    while (i < b.length && b[i] == 0)++i;
    if (b.length - i != n - 1 || b[i] != 2) return null;
    ++i;
    while (b[i] != 0)
        if (++i >= b.length) return null;
    var ret = "";
    while (++i < b.length)
    {
        var c = b[i] & 255;
        if (c < 128)
        { // utf-8 decode
            ret += String.fromCharCode(c);
        }
        else if ((c > 191) && (c < 224))
        {
            ret += String.fromCharCode(((c & 31) << 6) | (b[i + 1] & 63));
            ++i;
        }
        else
        {
            ret += String.fromCharCode(((c & 15) << 12) | ((b[i + 1] & 63) << 6) | (b[i + 2] & 63));
            i += 2;
        }
    }
    return ret;
}

// Set the private key fields N, e, and d from hex strings
function RSASetPrivate(N, E, D)
{
    if (N != null && E != null && N.length > 0 && E.length > 0)
    {
        this.n = parseBigInt(N, 16);
        this.e = parseInt(E, 16);
        this.d = parseBigInt(D, 16);
    }
    else alert("Invalid RSA private key");
}

// Set the private key fields N, e, d and CRT params from hex strings
function RSASetPrivateEx(N, E, D, P, Q, DP, DQ, C)
{
    if (N != null && E != null && N.length > 0 && E.length > 0)
    {
        this.n = parseBigInt(N, 16);
        this.e = parseInt(E, 16);
        this.d = parseBigInt(D, 16);
        this.p = parseBigInt(P, 16);
        this.q = parseBigInt(Q, 16);
        this.dmp1 = parseBigInt(DP, 16);
        this.dmq1 = parseBigInt(DQ, 16);
        this.coeff = parseBigInt(C, 16);
    }
    else alert("Invalid RSA private key");
}

// Generate a new random private key B bits long, using public expt E
function RSAGenerate(B, E)
{
    var rng = new SeededRandom();
    var qs = B >> 1;
    this.e = parseInt(E, 16);
    var ee = new BigInteger(E, 16);
    for (;;)
    {
        for (;;)
        {
            this.p = new BigInteger(B - qs, 1, rng);
            if (this.p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.p.isProbablePrime(10)) break;
        }
        for (;;)
        {
            this.q = new BigInteger(qs, 1, rng);
            if (this.q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.q.isProbablePrime(10)) break;
        }
        if (this.p.compareTo(this.q) <= 0)
        {
            var t = this.p;
            this.p = this.q;
            this.q = t;
        }
        var p1 = this.p.subtract(BigInteger.ONE);
        var q1 = this.q.subtract(BigInteger.ONE);
        var phi = p1.multiply(q1);

        if (phi.gcd(ee).compareTo(BigInteger.ONE) == 0)
        {
            this.n = this.p.multiply(this.q);
            this.d = ee.modInverse(phi);
            this.dmp1 = this.d.mod(p1);
            this.dmq1 = this.d.mod(q1);
            this.coeff = this.q.modInverse(this.p);
            break;
        }
    }
}

// Generate a new private key for known p and q using public expt E
function RSAGenerateByPQ(p, q, E)
{

    this.e = parseInt(E, 16);
    var ee = new BigInteger(E, 16);

    this.p = new BigInteger(p, 16);
    if (!this.p.isProbablePrime(10)) {
        throw Error("p should be prime!")
    }

    var qt = new BigInteger("01", 16); // whole q
    var q1 = new BigInteger("01", 16); // phi(q)

    if (q instanceof Array) {
        for(i=0; i<q.length; i++){
            q[i] = new BigInteger(q[i], 16);
            qt = qt.multiply(q[i]);
            q1 = q1.multiply(q[i].subtract(BigInteger.ONE));
        }
        this.q = qt;
    } else {
        this.q = new BigInteger(q, 16);
    }

    var p1 = this.p.subtract(BigInteger.ONE);
    //var q1 = this.q.subtract(BigInteger.ONE); // for prime q only

    var phi = p1.multiply(q1);
    if (phi.gcd(ee).compareTo(BigInteger.ONE) == 0) {
        this.n = this.p.multiply(this.q);
        this.d = ee.modInverse(phi);
        this.dmp1 = this.d.mod(p1);
        this.dmq1 = this.d.mod(q1);
        this.coeff = this.q.modInverse(this.p);
    } else {
        throw Error("Bad p or q")
    }
}


// Perform raw private operation on "x": return x^d (mod n)
function RSADoPrivate(x)
{
    if (this.p == null || this.q == null) return x.modPow(this.d, this.n);
    // TODO: re-calculate any missing CRT params
    var xp = x.mod(this.p).modPow(this.dmp1, this.p);
    var xq = x.mod(this.q).modPow(this.dmq1, this.q);
    while (xp.compareTo(xq) < 0)
        xp = xp.add(this.p);
    return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
}

// Return the PKCS#1 RSA decryption of "ctext".
// "ctext" is an even-length hex string and the output is a plain string.
function RSADecrypt(ctext)
{
    var c = parseBigInt(ctext, 16);
    var m = this.doPrivate(c);
    if (m == null) return null;
    return pkcs1unpad2(m, (this.n.bitLength() + 7) >> 3);
}

// protected
RSAKey.prototype.doPrivate = RSADoPrivate;

// public
RSAKey.prototype.setPrivate = RSASetPrivate;
RSAKey.prototype.setPrivateEx = RSASetPrivateEx;
RSAKey.prototype.generate = RSAGenerate;
RSAKey.prototype.generateByPQ = RSAGenerateByPQ;
RSAKey.prototype.decrypt = RSADecrypt;


//
// rsa-sign.js - adding signing functions to RSAKey class.
//
//
// version: 1.0 (2010-Jun-03)
//
// Copyright (c) 2010 Kenji Urushima (kenji.urushima@gmail.com)
//
// This software is licensed under the terms of the MIT License.
// http://www.opensource.org/licenses/mit-license.php
//
// The above copyright and license notice shall be
// included in all copies or substantial portions of the Software.
//
// Depends on:
//   function sha1.hex(s) of sha1.js
//   jsbn.js
//   jsbn2.js
//   rsa.js
//   rsa2.js
//
// keysize / pmstrlen
//  512 /  128
// 1024 /  256
// 2048 /  512
// 4096 / 1024
// As for _RSASGIN_DIHEAD values for each hash algorithm, see PKCS#1 v2.1 spec (p38).
var _RSASIGN_DIHEAD = [];
_RSASIGN_DIHEAD['sha1'] = "3021300906052b0e03021a05000414";
_RSASIGN_DIHEAD['sha256'] = "3031300d060960864801650304020105000420";
//_RSASIGN_DIHEAD['md2'] = "3020300c06082a864886f70d020205000410";
//_RSASIGN_DIHEAD['md5'] = "3020300c06082a864886f70d020505000410";
//_RSASIGN_DIHEAD['sha384'] = "3041300d060960864801650304020205000430";
//_RSASIGN_DIHEAD['sha512'] = "3051300d060960864801650304020305000440";
var _RSASIGN_HASHHEXFUNC = [];
_RSASIGN_HASHHEXFUNC['sha1'] = sha1.hex;
_RSASIGN_HASHHEXFUNC['sha256'] = sha256.hex;

// ========================================================================
// Signature Generation
// ========================================================================

function _rsasign_getHexPaddedDigestInfoForString(s, keySize, hashAlg)
{
    var pmStrLen = keySize / 4;
    var hashFunc = _RSASIGN_HASHHEXFUNC[hashAlg];
    var sHashHex = hashFunc(s);

    var sHead = "0001";
    var sTail = "00" + _RSASIGN_DIHEAD[hashAlg] + sHashHex;
    var sMid = "";
    var fLen = pmStrLen - sHead.length - sTail.length;
    for (var i = 0; i < fLen; i += 2)
    {
        sMid += "ff";
    }
    sPaddedMessageHex = sHead + sMid + sTail;
    return sPaddedMessageHex;
}

function _rsasign_signString(s, hashAlg)
{
    var hPM = _rsasign_getHexPaddedDigestInfoForString(s, this.n.bitLength(), hashAlg);
    var biPaddedMessage = parseBigInt(hPM, 16);
    var biSign = this.doPrivate(biPaddedMessage);
    var hexSign = biSign.toString(16);
    return hexSign;
}

function _rsasign_signStringWithSHA1(s)
{
    var hPM = _rsasign_getHexPaddedDigestInfoForString(s, this.n.bitLength(), 'sha1');
    var biPaddedMessage = parseBigInt(hPM, 16);
    var biSign = this.doPrivate(biPaddedMessage);
    var hexSign = biSign.toString(16);
    return hexSign;
}

function _rsasign_signStringWithSHA256(s)
{
    var hPM = _rsasign_getHexPaddedDigestInfoForString(s, this.n.bitLength(), 'sha256');
    var biPaddedMessage = parseBigInt(hPM, 16);
    var biSign = this.doPrivate(biPaddedMessage);
    var hexSign = biSign.toString(16);
    return hexSign;
}

// ========================================================================
// Signature Verification
// ========================================================================

function _rsasign_getDecryptSignatureBI(biSig, hN, hE)
{
    var rsa = new RSAKey();
    rsa.setPublic(hN, hE);
    var biDecryptedSig = rsa.doPublic(biSig);
    return biDecryptedSig;
}

function _rsasign_getHexDigestInfoFromSig(biSig, hN, hE)
{
    var biDecryptedSig = _rsasign_getDecryptSignatureBI(biSig, hN, hE);
    var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
    return hDigestInfo;
}

function _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo)
{
    for (var algName in _RSASIGN_DIHEAD)
    {
        var head = _RSASIGN_DIHEAD[algName];
        var len = head.length;
        if (hDigestInfo.substring(0, len) == head)
        {
            var a = [algName, hDigestInfo.substring(len)];
            return a;
        }
    }
    return [];
}

function _rsasign_verifySignatureWithArgs(sMsg, biSig, hN, hE)
{
    var hDigestInfo = _rsasign_getHexDigestInfoFromSig(biSig, hN, hE);
    var digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);
    if (digestInfoAry.length == 0) return false;
    var algName = digestInfoAry[0];
    var diHashValue = digestInfoAry[1];
    var ff = _RSASIGN_HASHHEXFUNC[algName];
    var msgHashValue = ff(sMsg);
    return (diHashValue == msgHashValue);
}

function _rsasign_verifyHexSignatureForMessage(hSig, sMsg)
{
    var biSig = parseBigInt(hSig, 16);
    var result = _rsasign_verifySignatureWithArgs(sMsg, biSig, this.n.toString(16), this.e.toString(16));
    return result;
}

function _rsasign_verifyString(sMsg, hSig)
{
    hSig = hSig.replace(/[ \n]+/g, "");
    var biSig = parseBigInt(hSig, 16);
    var biDecryptedSig = this.doPublic(biSig);
    var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
    var digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);

    if (digestInfoAry.length == 0) return false;
    var algName = digestInfoAry[0];
    var diHashValue = digestInfoAry[1];
    var ff = _RSASIGN_HASHHEXFUNC[algName];
    var msgHashValue = ff(sMsg);
    return (diHashValue == msgHashValue);
}

RSAKey.prototype.signString = _rsasign_signString;
RSAKey.prototype.signStringWithSHA1 = _rsasign_signStringWithSHA1;
RSAKey.prototype.signStringWithSHA256 = _rsasign_signStringWithSHA256;

RSAKey.prototype.verifyString = _rsasign_verifyString;
RSAKey.prototype.verifyHexSignatureForMessage = _rsasign_verifyHexSignatureForMessage;



























/*
 *  jsaes version 0.1  -  Copyright 2006 B. Poettering
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation; either version 2 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 *  02111-1307 USA
 */

// later modifications by wwwtyro@github

var aes = (function () {

    var my = {};

    my.Sbox = new Array(99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22);

    my.ShiftRowTab = new Array(0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11);

    my.Init = function () {
        my.Sbox_Inv = new Array(256);
        for (var i = 0; i < 256; i++)
            my.Sbox_Inv[my.Sbox[i]] = i;

        my.ShiftRowTab_Inv = new Array(16);
        for (var i = 0; i < 16; i++)
            my.ShiftRowTab_Inv[my.ShiftRowTab[i]] = i;

        my.xtime = new Array(256);
        for (var i = 0; i < 128; i++) {
            my.xtime[i] = i << 1;
            my.xtime[128 + i] = (i << 1) ^ 0x1b;
        }
    }

    my.Done = function () {
        delete my.Sbox_Inv;
        delete my.ShiftRowTab_Inv;
        delete my.xtime;
    }

    my.ExpandKey = function (key) {
        var kl = key.length,
            ks, Rcon = 1;
        switch (kl) {
            case 16:
                ks = 16 * (10 + 1);
                break;
            case 24:
                ks = 16 * (12 + 1);
                break;
            case 32:
                ks = 16 * (14 + 1);
                break;
            default:
                alert("my.ExpandKey: Only key lengths of 16, 24 or 32 bytes allowed!");
        }
        for (var i = kl; i < ks; i += 4) {
            var temp = key.slice(i - 4, i);
            if (i % kl == 0) {
                temp = new Array(my.Sbox[temp[1]] ^ Rcon, my.Sbox[temp[2]], my.Sbox[temp[3]], my.Sbox[temp[0]]);
                if ((Rcon <<= 1) >= 256) Rcon ^= 0x11b;
            }
            else if ((kl > 24) && (i % kl == 16)) temp = new Array(my.Sbox[temp[0]], my.Sbox[temp[1]], my.Sbox[temp[2]], my.Sbox[temp[3]]);
            for (var j = 0; j < 4; j++)
                key[i + j] = key[i + j - kl] ^ temp[j];
        }
    }

    my.Encrypt = function (block, key) {
        var l = key.length;
        my.AddRoundKey(block, key.slice(0, 16));
        for (var i = 16; i < l - 16; i += 16) {
            my.SubBytes(block, my.Sbox);
            my.ShiftRows(block, my.ShiftRowTab);
            my.MixColumns(block);
            my.AddRoundKey(block, key.slice(i, i + 16));
        }
        my.SubBytes(block, my.Sbox);
        my.ShiftRows(block, my.ShiftRowTab);
        my.AddRoundKey(block, key.slice(i, l));
    }

    my.Decrypt = function (block, key) {
        var l = key.length;
        my.AddRoundKey(block, key.slice(l - 16, l));
        my.ShiftRows(block, my.ShiftRowTab_Inv);
        my.SubBytes(block, my.Sbox_Inv);
        for (var i = l - 32; i >= 16; i -= 16) {
            my.AddRoundKey(block, key.slice(i, i + 16));
            my.MixColumns_Inv(block);
            my.ShiftRows(block, my.ShiftRowTab_Inv);
            my.SubBytes(block, my.Sbox_Inv);
        }
        my.AddRoundKey(block, key.slice(0, 16));
    }

    my.SubBytes = function (state, sbox) {
        for (var i = 0; i < 16; i++)
            state[i] = sbox[state[i]];
    }

    my.AddRoundKey = function (state, rkey) {
        for (var i = 0; i < 16; i++)
            state[i] ^= rkey[i];
    }

    my.ShiftRows = function (state, shifttab) {
        var h = new Array().concat(state);
        for (var i = 0; i < 16; i++)
            state[i] = h[shifttab[i]];
    }

    my.MixColumns = function (state) {
        for (var i = 0; i < 16; i += 4) {
            var s0 = state[i + 0],
                s1 = state[i + 1];
            var s2 = state[i + 2],
                s3 = state[i + 3];
            var h = s0 ^ s1 ^ s2 ^ s3;
            state[i + 0] ^= h ^ my.xtime[s0 ^ s1];
            state[i + 1] ^= h ^ my.xtime[s1 ^ s2];
            state[i + 2] ^= h ^ my.xtime[s2 ^ s3];
            state[i + 3] ^= h ^ my.xtime[s3 ^ s0];
        }
    }

    my.MixColumns_Inv = function (state) {
        for (var i = 0; i < 16; i += 4) {
            var s0 = state[i + 0],
                s1 = state[i + 1];
            var s2 = state[i + 2],
                s3 = state[i + 3];
            var h = s0 ^ s1 ^ s2 ^ s3;
            var xh = my.xtime[h];
            var h1 = my.xtime[my.xtime[xh ^ s0 ^ s2]] ^ h;
            var h2 = my.xtime[my.xtime[xh ^ s1 ^ s3]] ^ h;
            state[i + 0] ^= h1 ^ my.xtime[s0 ^ s1];
            state[i + 1] ^= h2 ^ my.xtime[s1 ^ s2];
            state[i + 2] ^= h1 ^ my.xtime[s2 ^ s3];
            state[i + 3] ^= h2 ^ my.xtime[s3 ^ s0];
        }
    }

    return my;

}());var cryptico = module.exports = (function() {

    var my = {};

    aes.Init();

    var base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

    my.b256to64 = function(t) {
        var a, c, n;
        var r = '', l = 0, s = 0;
        var tl = t.length;
        for (n = 0; n < tl; n++)
        {
            c = t.charCodeAt(n);
            if (s == 0)
            {
                r += base64Chars.charAt((c >> 2) & 63);
                a = (c & 3) << 4;
            }
            else if (s == 1)
            {
                r += base64Chars.charAt((a | (c >> 4) & 15));
                a = (c & 15) << 2;
            }
            else if (s == 2)
            {
                r += base64Chars.charAt(a | ((c >> 6) & 3));
                l += 1;
                r += base64Chars.charAt(c & 63);
            }
            l += 1;
            s += 1;
            if (s == 3) s = 0;
        }
        if (s > 0)
        {
            r += base64Chars.charAt(a);
            l += 1;
            r += '=';
            l += 1;
        }
        if (s == 1)
        {
            r += '=';
        }
        return r;
    }

    my.b64to256 = function(t)
    {
        var c, n;
        var r = '', s = 0, a = 0;
        var tl = t.length;
        for (n = 0; n < tl; n++)
        {
            c = base64Chars.indexOf(t.charAt(n));
            if (c >= 0)
            {
                if (s) r += String.fromCharCode(a | (c >> (6 - s)) & 255);
                s = (s + 2) & 7;
                a = (c << s) & 255;
            }
        }
        return r;
    }

    my.b16to64 = function(h) {
        var i;
        var c;
        var ret = "";
        if(h.length % 2 == 1)
        {
            h = "0" + h;
        }
        for (i = 0; i + 3 <= h.length; i += 3)
        {
            c = parseInt(h.substring(i, i + 3), 16);
            ret += base64Chars.charAt(c >> 6) + base64Chars.charAt(c & 63);
        }
        if (i + 1 == h.length)
        {
            c = parseInt(h.substring(i, i + 1), 16);
            ret += base64Chars.charAt(c << 2);
        }
        else if (i + 2 == h.length)
        {
            c = parseInt(h.substring(i, i + 2), 16);
            ret += base64Chars.charAt(c >> 2) + base64Chars.charAt((c & 3) << 4);
        }
        while ((ret.length & 3) > 0) ret += "=";
        return ret;
    }

    my.b64to16 = function(s) {
        var ret = "";
        var i;
        var k = 0;
        var slop;
        for (i = 0; i < s.length; ++i)
        {
            if (s.charAt(i) == "=") break;
            v = base64Chars.indexOf(s.charAt(i));
            if (v < 0) continue;
            if (k == 0)
            {
                ret += int2char(v >> 2);
                slop = v & 3;
                k = 1;
            }
            else if (k == 1)
            {
                ret += int2char((slop << 2) | (v >> 4));
                slop = v & 0xf;
                k = 2;
            }
            else if (k == 2)
            {
                ret += int2char(slop);
                ret += int2char(v >> 2);
                slop = v & 3;
                k = 3;
            }
            else
            {
                ret += int2char((slop << 2) | (v >> 4));
                ret += int2char(v & 0xf);
                k = 0;
            }
        }
        if (k == 1) ret += int2char(slop << 2);
        return ret;
    }

    // Converts a string to a byte array.
    my.string2bytes = function(string)
    {
        var bytes = new Array();
        for(var i = 0; i < string.length; i++)
        {
            bytes.push(string.charCodeAt(i));
        }
        return bytes;
    }

    // Converts a byte array to a string.
    my.bytes2string = function(bytes)
    {
        var string = "";
        for(var i = 0; i < bytes.length; i++)
        {
            string += String.fromCharCode(bytes[i]);
        }
        return string;
    }

    // Returns a XOR b, where a and b are 16-byte byte arrays.
    my.blockXOR = function(a, b)
    {
        var xor = new Array(16);
        for(var i = 0; i < 16; i++)
        {
            xor[i] = a[i] ^ b[i];
        }
        return xor;
    }

    // Returns a 16-byte initialization vector.
    my.blockIV = function()
    {
        var r = new SecureRandom();
        var IV = new Array(16);
        r.nextBytes(IV);
        return IV;
    }

    // Returns a copy of bytes with zeros appended to the end
    // so that the (length of bytes) % 16 == 0.
    my.pad16 = function(bytes)
    {
        var newBytes = bytes.slice(0);
        var padding = (16 - (bytes.length % 16)) % 16;
        for(i = bytes.length; i < bytes.length + padding; i++)
        {
            newBytes.push(0);
        }
        return newBytes;
    }

    // Removes trailing zeros from a byte array.
    my.depad = function(bytes)
    {
        var newBytes = bytes.slice(0);
        while(newBytes[newBytes.length - 1] == 0)
        {
            newBytes = newBytes.slice(0, newBytes.length - 1);
        }
        return newBytes;
    }

    // AES CBC Encryption.
    my.encryptAESCBC = function(plaintext, key)
    {
        var exkey = key.slice(0);
        aes.ExpandKey(exkey);
        var blocks = my.string2bytes(plaintext);
        blocks = my.pad16(blocks);
        var encryptedBlocks = my.blockIV();
        for(var i = 0; i < blocks.length/16; i++)
        {
            var tempBlock = blocks.slice(i * 16, i * 16 + 16);
            var prevBlock = encryptedBlocks.slice((i) * 16, (i) * 16 + 16);
            tempBlock = my.blockXOR(prevBlock, tempBlock);
            aes.Encrypt(tempBlock, exkey);
            encryptedBlocks = encryptedBlocks.concat(tempBlock);
        }
        var ciphertext = my.bytes2string(encryptedBlocks);
        return my.b256to64(ciphertext)
    }

    // AES CBC Decryption.
    my.decryptAESCBC = function(encryptedText, key)
    {
        var exkey = key.slice(0);
        aes.ExpandKey(exkey);
        var encryptedText = my.b64to256(encryptedText);
        var encryptedBlocks = my.string2bytes(encryptedText);
        var decryptedBlocks = new Array();
        for(var i = 1; i < encryptedBlocks.length/16; i++)
        {
            var tempBlock = encryptedBlocks.slice(i * 16, i * 16 + 16);
            var prevBlock = encryptedBlocks.slice((i-1) * 16, (i-1) * 16 + 16);
            aes.Decrypt(tempBlock, exkey);
            tempBlock = my.blockXOR(prevBlock, tempBlock);
            decryptedBlocks = decryptedBlocks.concat(tempBlock);
        }
        decryptedBlocks = my.depad(decryptedBlocks);
        return my.bytes2string(decryptedBlocks);
    }

    // Wraps a string to 60 characters.
    my.wrap60 = function(string)
    {
        var outstr = "";
        for(var i = 0; i < string.length; i++) {
            if(i % 60 == 0 && i != 0) outstr += "\n";
            outstr += string[i]; }
        return outstr;
    }

    // Generate a random key for the AES-encrypted message.
    my.generateAESKey = function()
    {
        var key = new Array(32);
        var r = new SecureRandom();
        r.nextBytes(key);
        return key;
    }

    // Generates an RSA key from a passphrase.
    my.generateRSAKey = function(passphrase, bitlength)
    {
        Math.seedrandom(sha256.hex(passphrase));
        var rsa = new RSAKey();
        rsa.generate(bitlength, "03");
        return rsa;
    }

    // Returns the ascii-armored version of the public key.
    my.publicKeyString = function(rsakey)
    {
        pubkey = my.b16to64(rsakey.n.toString(16));
        return pubkey;
    }

    // Returns an MD5 sum of a publicKeyString for easier identification.
    my.publicKeyID = function(publicKeyString)
    {
        return MD5(publicKeyString);
    }

    my.publicKeyFromString = function(string)
    {
        var N = my.b64to16(string.split("|")[0]);
        var E = "03";
        var rsa = new RSAKey();
        rsa.setPublic(N, E);
        return rsa
    }

    my.encrypt = function(plaintext, publickeystring, signingkey)
    {
        var cipherblock = "";
        var aeskey = my.generateAESKey();
        try
        {
            var publickey = my.publicKeyFromString(publickeystring);
            cipherblock += my.b16to64(publickey.encrypt(my.bytes2string(aeskey))) + "?";
        }
        catch(err)
        {
            return {status: "Invalid public key"};
        }
        if(signingkey)
        {
            signString = cryptico.b16to64(signingkey.signString(plaintext, "sha256"));
            plaintext += "::52cee64bb3a38f6403386519a39ac91c::";
            plaintext += cryptico.publicKeyString(signingkey);
            plaintext += "::52cee64bb3a38f6403386519a39ac91c::";
            plaintext += signString;
        }
        cipherblock += my.encryptAESCBC(plaintext, aeskey);
        return {status: "success", cipher: cipherblock};
    }

    my.decrypt = function(ciphertext, key)
    {
        var cipherblock = ciphertext.split("?");
        var aeskey = key.decrypt(my.b64to16(cipherblock[0]));
        if(aeskey == null)
        {
            return {status: "failure"};
        }
        aeskey = my.string2bytes(aeskey);
        var plaintext = my.decryptAESCBC(cipherblock[1], aeskey).split("::52cee64bb3a38f6403386519a39ac91c::");
        if(plaintext.length == 3)
        {
            var publickey = my.publicKeyFromString(plaintext[1]);
            var signature = my.b64to16(plaintext[2]);
            if(publickey.verifyString(plaintext[0], signature))
            {
                return {status: "success",
                    plaintext: plaintext[0],
                    signature: "verified",
                    publicKeyString: my.publicKeyString(publickey)};
            }
            else
            {
                return {status: "success",
                    plaintext: plaintext[0],
                    signature: "forged",
                    publicKeyString: my.publicKeyString(publickey)};
            }
        }
        else
        {
            return {status: "success", plaintext: plaintext[0], signature: "unsigned"};
        }
    }

    return my;

}());

module.exports.RSAKey = RSAKey;
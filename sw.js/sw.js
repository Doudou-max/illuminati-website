'use strict';
var ca = function(a) {
    function b(d) {
        return a.next(d)
    }
    function c(d) {
        return a.throw(d)
    }
    return new Promise(function(d, e) {
        function f(g) {
            g.done ? d(g.value) : Promise.resolve(g.value).then(b, c).then(f, e)
        }
        f(a.next())
    }
    )
}
  , h = function(a) {
    return ca(a())
};
/*

 Copyright The Closure Library Authors.
 SPDX-License-Identifier: Apache-2.0
*/
var p = this || self;
var t, y;
a: {
    for (var da = ["CLOSURE_FLAGS"], A = p, B = 0; B < da.length; B++)
        if (A = A[da[B]],
        A == null) {
            y = null;
            break a
        }
    y = A
}
var ea = y && y[610401301];
t = ea != null ? ea : !1;
var E;
const fa = p.navigator;
E = fa ? fa.userAgentData || null : null;
function F(a) {
    return t ? E ? E.brands.some( ({brand: b}) => b && b.indexOf(a) != -1) : !1 : !1
}
function G(a) {
    var b;
    a: {
        const c = p.navigator;
        if (c) {
            const d = c.userAgent;
            if (d) {
                b = d;
                break a
            }
        }
        b = ""
    }
    return b.indexOf(a) != -1
}
;function H() {
    return t ? !!E && E.brands.length > 0 : !1
}
function I() {
    return H() ? F("Chromium") : (G("Chrome") || G("CriOS")) && !(H() ? 0 : G("Edge")) || G("Silk")
}
;!G("Android") || I();
I();
G("Safari") && (I() || (H() ? 0 : G("Coast")) || (H() ? 0 : G("Opera")) || (H() ? 0 : G("Edge")) || (H() ? F("Microsoft Edge") : G("Edg/")) || H() && F("Opera"));
var ha = {}
  , J = null
  , ja = function(a) {
    var b = 3;
    b === void 0 && (b = 0);
    ia();
    const c = ha[b]
      , d = Array(Math.floor(a.length / 3))
      , e = c[64] || "";
    let f = 0
      , g = 0;
    for (; f < a.length - 2; f += 3) {
        const n = a[f]
          , q = a[f + 1]
          , u = a[f + 2]
          , w = c[n >> 2]
          , m = c[(n & 3) << 4 | q >> 4]
          , r = c[(q & 15) << 2 | u >> 6]
          , v = c[u & 63];
        d[g++] = "" + w + m + r + v
    }
    let k = 0
      , l = e;
    switch (a.length - f) {
    case 2:
        k = a[f + 1],
        l = c[(k & 15) << 2] || e;
    case 1:
        const n = a[f];
        d[g] = "" + c[n >> 2] + c[(n & 3) << 4 | k >> 4] + l + e
    }
    return d.join("")
}
  , K = function(a) {
    const b = a.length;
    let c = b * 3 / 4;
    c % 3 ? c = Math.floor(c) : "=.".indexOf(a[b - 1]) != -1 && (c = "=.".indexOf(a[b - 2]) != -1 ? c - 2 : c - 1);
    const d = new Uint8Array(c);
    let e = 0;
    ka(a, function(f) {
        d[e++] = f
    });
    return e !== c ? d.subarray(0, e) : d
}
  , ka = function(a, b) {
    function c(e) {
        for (; d < a.length; ) {
            const f = a.charAt(d++)
              , g = J[f];
            if (g != null)
                return g;
            if (!/^[\s\xa0]*$/.test(f))
                throw Error("Unknown base64 encoding at char: " + f);
        }
        return e
    }
    ia();
    let d = 0;
    for (; ; ) {
        const e = c(-1)
          , f = c(0)
          , g = c(64)
          , k = c(64);
        if (k === 64 && e === -1)
            break;
        b(e << 2 | f >> 4);
        g != 64 && (b(f << 4 & 240 | g >> 2),
        k != 64 && b(g << 6 & 192 | k))
    }
}
  , ia = function() {
    if (!J) {
        J = {};
        var a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".split("")
          , b = ["+/=", "+/", "-_=", "-_.", "-_"];
        for (let c = 0; c < 5; c++) {
            const d = a.concat(b[c].split(""));
            ha[c] = d;
            for (let e = 0; e < d.length; e++) {
                const f = d[e];
                J[f] === void 0 && (J[f] = e)
            }
        }
    }
};
/*

 Copyright 2020 Google LLC
 SPDX-License-Identifier: Apache-2.0
*/
var L = class extends Error {
    constructor(a) {
        super(a);
        Object.setPrototypeOf(this, L.prototype)
    }
}
;
L.prototype.name = "SecurityException";
var M = class extends Error {
    constructor(a) {
        super(a);
        Object.setPrototypeOf(this, M.prototype)
    }
}
;
M.prototype.name = "InvalidArgumentsException";
function N(...a) {
    let b = 0;
    for (let e = 0; e < arguments.length; e++)
        b += arguments[e].length;
    const c = new Uint8Array(b);
    let d = 0;
    for (let e = 0; e < arguments.length; e++)
        c.set(arguments[e], d),
        d += arguments[e].length;
    return c
}
function O(a) {
    const b = a.replace(/-/g, "+").replace(/_/g, "/");
    return P(globalThis.atob(b))
}
function la(a) {
    let b = "";
    for (let c = 0; c < a.length; c += 1)
        b += String.fromCharCode(a[c]);
    return globalThis.btoa(b).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_")
}
function P(a) {
    const b = [];
    let c = 0;
    for (let d = 0; d < a.length; d++) {
        const e = a.charCodeAt(d);
        b[c++] = e
    }
    return new Uint8Array(b)
}
;/*

 Copyright 2022 Google LLC
 SPDX-License-Identifier: Apache-2.0
*/
var ma = function(a, b, c, d) {
    return h(function*() {
        if (c.length < (a.l ? 28 : 16))
            throw new L("ciphertext too short");
        if (b.length !== 12)
            throw new L("IV must be 12 bytes");
        const e = {
            name: "AES-GCM",
            iv: b,
            tagLength: 128
        };
        d && (e.additionalData = d);
        const f = a.l ? new Uint8Array(c.subarray(12)) : c;
        try {
            return new Uint8Array(yield globalThis.crypto.subtle.decrypt(e, a.key, f))
        } catch (g) {
            throw new L(g.toString());
        }
    })
}
  , na = class {
    constructor({key: a, l: b}) {
        this.key = a;
        this.l = b
    }
    encrypt(a, b, c) {
        const d = this;
        return h(function*() {
            if (a.length !== 12)
                throw new L("IV must be 12 bytes");
            const e = {
                name: "AES-GCM",
                iv: a,
                tagLength: 128
            };
            c && (e.additionalData = c);
            const f = yield globalThis.crypto.subtle.encrypt(e, d.key, b);
            return d.l ? N(a, new Uint8Array(f)) : new Uint8Array(f)
        })
    }
}
;
function oa({key: a, l: b}) {
    return h(function*() {
        if (![16, 32].includes(a.length))
            throw new M("unsupported AES key size: ${n}");
        const c = yield globalThis.crypto.subtle.importKey("raw", a, {
            name: "AES-GCM",
            length: a.length
        }, !1, ["encrypt", "decrypt"]);
        return new na({
            key: c,
            l: b
        })
    })
}
;function pa(a) {
    switch (a) {
    case 1:
        return "P-256";
    case 2:
        return "P-384";
    case 3:
        return "P-521"
    }
}
function Q(a) {
    switch (a) {
    case "P-256":
        return 1;
    case "P-384":
        return 2;
    case "P-521":
        return 3
    }
    throw new M("unknown curve: " + a);
}
function S(a) {
    switch (a) {
    case 1:
        return 32;
    case 2:
        return 48;
    case 3:
        return 66
    }
}
function qa(a, b) {
    return h(function*() {
        const c = a.algorithm.namedCurve;
        if (!c)
            throw new M("namedCurve must be provided");
        const d = Object.assign({}, {
            "public": b
        }, a.algorithm)
          , e = 8 * S(Q(c))
          , f = yield globalThis.crypto.subtle.deriveBits(d, a, e);
        return new Uint8Array(f)
    })
}
function ra(a) {
    return h(function*() {
        return yield globalThis.crypto.subtle.generateKey({
            name: "ECDH",
            namedCurve: a
        }, !0, ["deriveKey", "deriveBits"])
    })
}
function sa(a) {
    return h(function*() {
        const b = yield globalThis.crypto.subtle.exportKey("jwk", a);
        if (b.crv === void 0)
            throw new M("crv must be provided");
        const c = S(Q(b.crv));
        if (b.x === void 0)
            throw new M("x must be provided");
        if (b.y === void 0)
            throw new M("y must be provided");
        const d = O(b.x);
        if (d.length !== c)
            throw new M(`x-coordinate byte-length is invalid (got: ${d.length}, want: ${c}).`);
        const e = O(b.y);
        if (e.length !== c)
            throw new M(`y-coordinate byte-length is invalid (got: ${e.length}, want: ${c}).`);
        return b
    })
}
function ta(a) {
    return h(function*() {
        const b = a.crv;
        if (!b)
            throw new M("crv must be provided");
        return yield globalThis.crypto.subtle.importKey("jwk", a, {
            name: "ECDH",
            namedCurve: b
        }, !0, [])
    })
}
;var ua = T(1, 0)
  , va = T(2, 16)
  , wa = T(2, 18)
  , xa = T(2, 1)
  , ya = T(2, 3)
  , za = T(2, 1)
  , Aa = T(2, 2)
  , Ba = P("KEM")
  , Ca = P("HPKE")
  , Da = P("HPKE-v1");
function T(a, b) {
    const c = new Uint8Array(a);
    for (let d = 0; d < a; d++)
        c[d] = b >> 8 * (a - d - 1) & 255;
    return c
}
function Ea({J: a, I: b, D: c}) {
    return N(Ca, a, b, c)
}
function Fa({o: a, m: b, i: c}) {
    return N(Da, c, P(a), b)
}
function Ha({s: a, info: b, i: c, length: d}) {
    return N(T(2, d), Da, c, P(a), b)
}
function Ia(a, b) {
    return h(function*() {
        var c;
        {
            const d = S(Q(a));
            if (b.length !== 1 + 2 * d || b[0] !== 4)
                throw new L("invalid point");
            c = {
                kty: "EC",
                crv: a,
                x: la(new Uint8Array(b.subarray(1, 1 + d))),
                y: la(new Uint8Array(b.subarray(1 + d, b.length))),
                ext: !0
            }
        }
        return yield ta(c)
    })
}
function Ja(a) {
    return h(function*() {
        const b = a.algorithm
          , c = yield sa(a);
        if (!c.crv)
            throw new L("Curve has to be defined.");
        var d;
        {
            const e = S(Q(b.namedCurve))
              , f = c.x
              , g = c.y;
            if (f === void 0)
                throw new M("x must be provided");
            if (g === void 0)
                throw new M("y must be provided");
            const k = new Uint8Array(1 + 2 * e)
              , l = O(g)
              , n = O(f);
            k.set(l, 1 + 2 * e - l.length);
            k.set(n, 1 + e - n.length);
            k[0] = 4;
            d = k
        }
        return d
    })
}
;var Ka = class {
    constructor(a) {
        this.v = a
    }
    seal({key: a, nonce: b, K: c, A: d}) {
        const e = this;
        return h(function*() {
            if (a.length !== e.v)
                throw new L("Unexpected key length: " + a.length.toString());
            return yield(yield oa({
                key: a,
                l: !1
            })).encrypt(b, c, d)
        })
    }
    open({key: a, nonce: b, F: c, A: d}) {
        const e = this;
        return h(function*() {
            if (a.length !== e.v)
                throw new L("Unexpected key length: " + a.length.toString());
            return ma(yield oa({
                key: a,
                l: !1
            }), b, c, d)
        })
    }
}
;
var La = class {
}
;
function U(a) {
    if (a == null || !(a instanceof Uint8Array))
        throw new M("input must be a non null Uint8Array");
}
;var Ma = function(a, b) {
    return h(function*() {
        U(b);
        const c = yield globalThis.crypto.subtle.sign({
            name: "HMAC",
            hash: {
                name: a.hash
            }
        }, a.key, b);
        return new Uint8Array(c.slice(0, a.g))
    })
}
  , Na = class extends La {
    constructor(a, b, c) {
        super();
        this.hash = a;
        this.key = b;
        this.g = c
    }
}
;
function Oa(a, b, c) {
    return h(function*() {
        U(b);
        if (!Number.isInteger(c))
            throw new M("invalid tag size, must be an integer");
        if (c < 10)
            throw new M("tag too short, must be at least " + (10).toString() + " bytes");
        switch (a) {
        case "SHA-1":
            if (c > 20)
                throw new M("tag too long, must not be larger than 20 bytes");
            break;
        case "SHA-256":
            if (c > 32)
                throw new M("tag too long, must not be larger than 32 bytes");
            break;
        case "SHA-384":
            if (c > 48)
                throw new M("tag too long, must not be larger than 48 bytes");
            break;
        case "SHA-512":
            if (c > 64)
                throw new M("tag too long, must not be larger than 64 bytes");
            break;
        default:
            throw new M(a + " is not supported");
        }
        const d = yield globalThis.crypto.subtle.importKey("raw", b, {
            name: "HMAC",
            hash: {
                name: a
            },
            length: b.length * 8
        }, !1, ["sign", "verify"]);
        return new Na(a,d,c)
    })
}
;var Pa = function(a, b, c) {
    return h(function*() {
        U(b);
        const d = V(a);
        let e;
        ((e = c) == null ? 0 : e.length) || (c = new Uint8Array(d));
        U(c);
        return yield Ma(yield Oa(a.u, c, d), b)
    })
}
  , W = function(a, {m: b, o: c, i: d, salt: e}) {
    return h(function*() {
        return yield Pa(a, Fa({
            o: c,
            m: b,
            i: d
        }), e)
    })
}
  , Qa = function(a, b, c, d) {
    return h(function*() {
        if (!Number.isInteger(d))
            throw new L("length must be an integer");
        if (d <= 0)
            throw new L("length must be positive");
        const e = V(a);
        if (d > 255 * e)
            throw new L("length too large");
        U(c);
        const f = yield Oa(a.u, b, e);
        let g = 1
          , k = 0
          , l = new Uint8Array(0);
        const n = new Uint8Array(d);
        for (; ; ) {
            const q = new Uint8Array(l.length + c.length + 1);
            q.set(l, 0);
            q.set(c, l.length);
            q[q.length - 1] = g;
            l = yield Ma(f, q);
            if (k + l.length < d)
                n.set(l, k),
                k += l.length,
                g++;
            else {
                n.set(l.subarray(0, d - k), k);
                break
            }
        }
        return n
    })
}
  , Ra = function(a, {C: b, info: c, s: d, i: e, length: f}) {
    return h(function*() {
        return yield Qa(a, b, Ha({
            s: d,
            info: c,
            i: e,
            length: f
        }), f)
    })
}
  , Sa = function(a, {m: b, o: c, info: d, s: e, i: f, length: g, salt: k}) {
    return h(function*() {
        const l = yield Pa(a, Fa({
            o: c,
            m: b,
            i: f
        }), k);
        return yield Qa(a, l, Ha({
            s: e,
            info: d,
            i: f,
            length: g
        }), g)
    })
}
  , V = function(a) {
    switch (a.u) {
    case "SHA-256":
        return 32;
    case "SHA-512":
        return 64
    }
}
  , X = class {
    constructor(a) {
        this.u = a
    }
}
;
var Ta = function(a) {
    var b = a.g;
    const c = new Uint8Array(12);
    for (let f = 0; f < 12; f++)
        c[f] = Number(b >> BigInt(8 * (12 - f - 1))) & 255;
    var d = a.h;
    if (d.length !== c.length)
        throw new M("Both byte arrays should be of the same length");
    const e = new Uint8Array(d.length);
    for (let f = 0; f < e.length; f++)
        e[f] = d[f] ^ c[f];
    if (a.g >= a.j)
        throw new L("message limit reached");
    a.g += BigInt(1);
    return e
}
  , Ua = class {
    constructor(a, b, c, d) {
        this.B = a;
        this.key = b;
        this.h = c;
        this.aead = d;
        this.g = BigInt(0);
        this.j = (BigInt(1) << BigInt(96)) - BigInt(1)
    }
    seal(a, b) {
        const c = this;
        return h(function*() {
            const d = Ta(c);
            return yield c.aead.seal({
                key: c.key,
                nonce: d,
                K: a,
                A: b
            })
        })
    }
    open(a, b) {
        const c = this;
        return h(function*() {
            const d = Ta(c);
            return c.aead.open({
                key: c.key,
                nonce: d,
                F: a,
                A: b
            })
        })
    }
}
;
function Va(a, b, c, d, e, f) {
    return h(function*() {
        var g;
        a: {
            switch (e.v) {
            case 16:
                g = za;
                break a;
            case 32:
                g = Aa;
                break a
            }
            g = void 0
        }
        var k;
        a: {
            switch (d.u) {
            case "SHA-256":
                k = xa;
                break a;
            case "SHA-512":
                k = ya;
                break a
            }
            k = void 0
        }
        const l = Ea({
            J: Wa(c),
            I: k,
            D: g
        })
          , n = W(d, {
            m: new Uint8Array(0),
            o: "psk_id_hash",
            i: l
        })
          , q = yield W(d, {
            m: f,
            o: "info_hash",
            i: l
        })
          , u = yield n
          , w = N(ua, u, q)
          , m = yield W(d, {
            m: new Uint8Array(0),
            o: "secret",
            i: l,
            salt: b
        })
          , r = Ra(d, {
            C: m,
            info: w,
            s: "key",
            i: l,
            length: e.v
        })
          , v = yield Ra(d, {
            C: m,
            info: w,
            s: "base_nonce",
            i: l,
            length: 12
        })
          , x = yield r;
        return new Ua(a,x,v,e)
    })
}
function Xa(a, b, c, d, e) {
    return h(function*() {
        const f = yield Ya(b, a);
        return yield Va(f.B, f.L, b, c, d, e)
    })
}
;var Za = function(a) {
    return h(function*() {
        return yield Ja(a.publicKey)
    })
}
  , $a = class {
    constructor(a, b) {
        this.privateKey = a;
        this.publicKey = b
    }
}
;
function ab(a) {
    return h(function*() {
        bb(a.privateKey, "private");
        bb(a.publicKey, "public");
        return new $a(a.privateKey,a.publicKey)
    })
}
function bb(a, b) {
    if (b !== a.type)
        throw new M(`keyPair ${b} key was of type ${a.type}`);
    const c = a.algorithm;
    if ("ECDH" !== c.name)
        throw new M(`keyPair ${b} key should be ECDH but found ${c.name}`);
}
;var db = function(a) {
    switch (a) {
    case 1:
        return new cb(new X("SHA-256"),1);
    case 3:
        return new cb(new X("SHA-512"),3)
    }
}
  , Wa = function(a) {
    switch (a.g) {
    case 1:
        return va;
    case 3:
        return wa
    }
}
  , Ya = function(a, b) {
    return h(function*() {
        const c = yield ra(pa(a.g));
        return yield a.h(b, yield ab(c))
    })
}
  , eb = function(a, b, c, d) {
    return h(function*() {
        const e = N(c, d)
          , f = N(Ba, Wa(a));
        return yield Sa(a.j, {
            m: b,
            o: "eae_prk",
            info: e,
            s: "shared_secret",
            i: f,
            length: V(a.j)
        })
    })
}
  , cb = class {
    constructor(a, b) {
        this.j = a;
        this.g = b;
        this.TEST_ONLY = this.h
    }
    h(a, b) {
        const c = this;
        return h(function*() {
            const d = yield Ia(pa(c.g), a)
              , e = qa(b.privateKey, d)
              , f = yield Za(b)
              , g = yield e;
            return {
                L: yield eb(c, g, f, a),
                B: f
            }
        })
    }
}
;
/*

 Copyright 2024 Google LLC
 SPDX-License-Identifier: Apache-2.0
*/
function fb(a, b, c) {
    var d;
    return h(function*() {
        d || (d = new Uint8Array(0));
        let e, f, g;
        switch (a) {
        case 1:
            e = db(1);
            f = new X("SHA-256");
            g = new Ka(16);
            break;
        case 2:
            e = db(3);
            f = new X("SHA-512");
            g = new Ka(32);
            break;
        default:
            throw new L(`Unknown HPKE parameters: ${a}`);
        }
        const k = yield Xa(b, e, f, g, d)
          , l = yield k.seal(c, new Uint8Array(0));
        return N(k.B, l)
    })
}
;const gb = Number('_TEMPLATE_VARIABLE("var_encryption_timeout_ms")');
var hb = function(a, b, c, d) {
    return h(function*() {
        if (!c)
            return Y(9);
        if (!a.h)
            return Y(a.status);
        try {
            let g;
            const k = K((g = a.h) == null ? void 0 : g.hpkePublicKey.publicKey);
            if (!k || !a.g)
                return Y(11);
            const l = K(d(b))
              , n = yield fb(a.g, k, l);
            var e;
            if (n.length <= 8192)
                e = String.fromCharCode.apply(null, n);
            else {
                var f = "";
                for (let u = 0; u < n.length; u += 8192)
                    f += String.fromCharCode.apply(null, Array.prototype.slice.call(n, u, u + 8192));
                e = f
            }
            let q = d(e);
            q = q.replace(/\//g, "_");
            q = q.replace(/\+/g, "-");
            return Y(0, q)
        } catch (g) {
            return Y(6)
        }
    })
}
  , jb = class {
    constructor(a) {
        this.status = 13;
        if (a) {
            var b = a.hpkePublicKey.params.kem
              , c = a.hpkePublicKey.params.kdf
              , d = a.hpkePublicKey.params.aead;
            b === "DHKEM_P521_HKDF_SHA512" && c === "HKDF_SHA512" && d === "AES_256_GCM" ? (this.g = 2,
            this.h = a) : b === "DHKEM_P256_HKDF_SHA256" && c === "HKDF_SHA256" && d === "AES_128_GCM" ? (this.g = 1,
            this.h = a) : this.status = 7
        } else
            this.status = 8
    }
    encrypt(a, b, c) {
        const d = hb(this, a, !!b.crypto, b.btoa);
        return c || !gb ? d : Promise.race([d, ib().then( () => Y(14))])
    }
}
;
function Y(a, b) {
    return a === 0 ? {
        cipherText: b,
        status: a
    } : {
        status: a
    }
}
function ib() {
    return new Promise(a => void setTimeout(a, gb))
}
;function kb(a) {
    switch (a) {
    case 0:
        break;
    case 9:
        return "e4";
    case 6:
        return "e5";
    case 14:
        return "e6";
    default:
        return "e7"
    }
}
;const lb = /^[0-9A-Fa-f]{64}$/;
function mb(a) {
    try {
        return (new TextEncoder).encode(a)
    } catch (b) {
        const c = [];
        for (let d = 0; d < a.length; d++) {
            let e = a.charCodeAt(d);
            e < 128 ? c.push(e) : e < 2048 ? c.push(192 | e >> 6, 128 | e & 63) : e < 55296 || e >= 57344 ? c.push(224 | e >> 12, 128 | e >> 6 & 63, 128 | e & 63) : (e = 65536 + ((e & 1023) << 10 | a.charCodeAt(++d) & 1023),
            c.push(240 | e >> 18, 128 | e >> 12 & 63, 128 | e >> 6 & 63, 128 | e & 63))
        }
        return new Uint8Array(c)
    }
}
function nb(a, b) {
    if (a === "" || a === "e0")
        return Promise.resolve(a);
    let c;
    if ((c = b.crypto) == null ? 0 : c.subtle) {
        if (lb.test(a))
            return Promise.resolve(a);
        try {
            const d = mb(a);
            return b.crypto.subtle.digest("SHA-256", d).then(e => {
                const f = Array.from(new Uint8Array(e)).map(g => String.fromCharCode(g)).join("");
                return b.btoa(f).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
            }
            ).catch( () => "e2")
        } catch (d) {
            return Promise.resolve("e2")
        }
    } else
        return Promise.resolve("e1")
}
;var ob = class {
}
;
var pb = class extends ob {
    constructor(a) {
        super();
        this.key = a;
        this.g = new na({
            key: a,
            l: !0
        })
    }
    encrypt(a, b) {
        const c = this;
        return h(function*() {
            if (!Number.isInteger(12))
                throw new M("n must be a nonnegative integer");
            const d = new Uint8Array(12);
            globalThis.crypto.getRandomValues(d);
            return c.g.encrypt(d, a, b)
        })
    }
}
;
const Z = {};
function qb(a, b) {
    var c = globalThis.btoa;
    return h(function*() {
        Z[a] = Z[a] || rb(a);
        const d = yield sb()
          , e = tb(d)
          , f = (new pb(d)).encrypt(K(c(b)))
          , g = ub(yield Z[a], yield e);
        return {
            encryptedExportedAesKeyAsBase64: ja(new Uint8Array(yield g)),
            encryptedPayloadAsBase64: ja(yield f)
        }
    })
}
function sb() {
    return h(function*() {
        return globalThis.crypto.subtle.generateKey({
            name: "AES-GCM",
            length: 256
        }, !0, ["encrypt", "decrypt"])
    })
}
function tb(a) {
    return h(function*() {
        return globalThis.crypto.subtle.exportKey("raw", a)
    })
}
function ub(a, b) {
    return h(function*() {
        return globalThis.crypto.subtle.encrypt({
            name: "RSA-OAEP"
        }, a, b)
    })
}
function rb(a) {
    return h(function*() {
        return globalThis.crypto.subtle.importKey("spki", K(a), {
            name: "RSA-OAEP",
            hash: {
                name: "SHA-256"
            }
        }, !1, ["encrypt"])
    })
}
;/*
 jQuery (c) 2005, 2012 jQuery Foundation, Inc. jquery.org/license.
*/
var vb = /\[object (Boolean|Number|String|Function|Array|Date|RegExp)\]/
  , wb = function(a) {
    var b;
    if (!(b = !a)) {
        var c;
        if (a == null)
            c = String(a);
        else {
            var d = vb.exec(Object.prototype.toString.call(Object(a)));
            c = d ? d[1].toLowerCase() : "object"
        }
        b = c != "object"
    }
    if (b || a.nodeType || a == a.window)
        return !1;
    try {
        if (a.constructor && !Object.prototype.hasOwnProperty.call(Object(a), "constructor") && !Object.prototype.hasOwnProperty.call(Object(a.constructor.prototype), "isPrototypeOf"))
            return !1
    } catch (f) {
        return !1
    }
    for (var e in a)
        ;
    return e === void 0 || Object.prototype.hasOwnProperty.call(Object(a), e)
};
var xb = function(a, b) {
    b = a.g + b;
    let c = b.indexOf("\n\n");
    for (; c !== -1; ) {
        var d;
        a: {
            const [x,C] = b.substring(0, c).split("\n");
            if (x.indexOf("event: message") === 0 && C.indexOf("data: ") === 0)
                try {
                    d = JSON.parse(C.substring(C.indexOf(":") + 1));
                    break a
                } catch (z) {}
            d = void 0
        }
        var e = a
          , f = d;
        if (f) {
            var g = f.send_pixel
              , k = f.options
              , l = e.h;
            if (g) {
                var n = g || [];
                if (Array.isArray(n)) {
                    var q = wb(k) ? k : {};
                    for (const x of n)
                        l(x, q)
                }
            }
            var u = f.create_iframe
              , w = f.options
              , m = e.j;
            if (u && m) {
                var r = u || [];
                if (Array.isArray(r)) {
                    var v = wb(w) ? w : {};
                    for (const x of r)
                        m(x, v)
                }
            }
        }
        b = b.substring(c + 2);
        c = b.indexOf("\n\n")
    }
    a.g = b
}
  , yb = class {
    constructor(a) {
        this.h = a;
        this.g = ""
    }
}
;
var zb = {
    M: 0,
    N: 1,
    0: "GET",
    1: "POST"
};
var Bb = function(a, b, c) {
    return h(function*() {
        var d;
        a: {
            try {
                const f = JSON.parse(c.encryptionKeyString || "").keys
                  , g = f[Math.floor(Math.random() * f.length)];
                d = g && g.hpkePublicKey && g.hpkePublicKey.params && g.hpkePublicKey.params.kem && g.hpkePublicKey.params.kdf && g.hpkePublicKey.params.aead && g.hpkePublicKey.version !== void 0 && g.id && g.hpkePublicKey.publicKey ? g : void 0;
                break a
            } catch (f) {}
            d = void 0
        }
        const e = d;
        return Ab(a, a.g.performance.now(), (e == null ? void 0 : e.id) || "undefined", !0, (new jb(e)).encrypt(b, a.g))
    })
}
  , Cb = function(a, b, c) {
    return h(function*() {
        return Ab(a, a.g.performance.now(), "unknown", !1, qb(c.encryptionKeyString || "", b).then(d => ({
            cipherText: d.encryptedPayloadAsBase64 + "!" + d.encryptedExportedAesKeyAsBase64,
            status: 0
        })))
    })
}
  , Fb = function(a, b) {
    return h(function*() {
        if (!b.url)
            return {
                failureType: 9,
                command: 0,
                data: "url required."
            };
        const c = yield Db(a, b);
        if ("failureType"in c)
            return c;
        yield Eb(a, c, b);
        return c
    })
}
  , Gb = function(a, b, c, d) {
    h(function*() {
        let e;
        const f = b.commandType
          , g = b.params;
        switch (f) {
        case 0:
            e = yield Fb(a, g);
            break;
        default:
            e = {
                failureType: 8,
                command: f,
                data: `Command with type ${f} unknown.`
            }
        }
        "failureType"in e ? d(e) : c(e)
    })
}
  , Db = function(a, b) {
    return h(function*() {
        function c(m) {
            return h(function*() {
                const [r,v] = m.split("|");
                let[x,C] = r.split(".")
                  , z = C
                  , D = k[x];
                D || (D = r,
                z = "");
                const ba = R => h(function*() {
                    try {
                        return yield u(v)(R)
                    } catch (aa) {
                        throw new Hb(aa.message);
                    }
                });
                if (!z) {
                    if (typeof D === "string")
                        return yield ba(D);
                    const R = D
                      , aa = Object.keys(R).map(Ga => h(function*() {
                        const Jb = yield ba(R[Ga]);
                        return `${Ga}=${Jb}`
                    }));
                    return (yield Promise.all(aa)).join("&")
                }
                return typeof D === "object" && D[z] ? yield ba(D[z]) : m
            })
        }
        function d(m) {
            return h(function*() {
                let r, v = "";
                for (; m.match(q) && v !== m; ) {
                    v = m;
                    r = m.matchAll(q);
                    const x = [...r].map(z => c(z[1]))
                      , C = yield Promise.all(x);
                    C.length !== 0 && (m = m.replace(q, z => C.shift() || z))
                }
                return m
            })
        }
        let {url: e, body: f} = b;
        const {attributionReporting: g, templates: k, processResponse: l, method: n=0} = b
          , q = RegExp("\\${([^${}]*?)}", "g")
          , u = m => {
            if (m == null)
                return v => h(function*() {
                    return v
                });
            const r = a.h[m];
            if (r == null)
                throw Error(`Unknown filter: ${m}`);
            return v => h(function*() {
                return yield r(v, b)
            })
        }
        ;
        try {
            e = yield d(e),
            f = f ? yield d(f) : void 0
        } catch (m) {
            return {
                failureType: 9,
                command: 0,
                data: `Failed to inject template values: ${m}`
            }
        }
        const w = {
            method: zb[n],
            credentials: "include",
            body: n === 1 ? f : void 0,
            keepalive: !0,
            redirect: "follow"
        };
        l || (w.mode = "no-cors");
        g && (w.attributionReporting = {
            eventSourceEligible: !1,
            triggerEligible: !0
        });
        try {
            const m = yield a.g.fetch(e, w);
            return l && !m.ok ? {
                failureType: 9,
                command: 0,
                data: "Fetch failed"
            } : {
                data: l ? yield m.text() : e
            }
        } catch (m) {
            return {
                failureType: 9,
                command: 0,
                data: `Fetch failed: ${m}`
            }
        }
    })
}
  , Eb = function(a, b, c) {
    return h(function*() {
        if (c.processResponse) {
            var d = [];
            xb(new yb( (e, f) => {
                d.push(Db(a, {
                    url: e,
                    method: 0,
                    templates: c.templates,
                    processResponse: !1,
                    attributionReporting: f.attribution_reporting
                }))
            }
            ), b.data);
            return Promise.all(d)
        }
    })
}
  , Ab = function(a, b, c, d, e) {
    return e.then(f => {
        const g = a.g.performance.now()
          , k = [`emkid.${c}~`, `ev.${(d ? l => l.replace(/./g, "*") : l => l)(f.cipherText || "")}`, `&_es=${f.status}`];
        b && g && k.push(`&_est=${Math.round(g) - Math.round(b)}`);
        return k.join("")
    }
    , () => [`ec.${kb(15)}`, "&_es=15"].join("")).catch( () => [`ec.${kb(16)}`, "&_es=16"].join(""))
}
  , Ib = class {
    constructor(a) {
        this.g = a;
        this.h = {
            sha256: b => {
                const c = this;
                return h(function*() {
                    return yield nb(b, c.g)
                })
            }
            ,
            encode: b => h(function*() {
                return encodeURIComponent(b)
            }),
            encrypt: (b, c) => {
                const d = this;
                return h(function*() {
                    return yield Bb(d, b, c)
                })
            }
            ,
            encryptRsa: (b, c) => {
                const d = this;
                return h(function*() {
                    return yield Cb(d, b, c)
                })
            }
        }
    }
}
;
class Hb extends Error {
    constructor(a) {
        super(a)
    }
}
;var Kb = function(a, b, c) {
    a.g[b] == null && (a.g[b] = 0,
    a.h[b] = c,
    a.j++);
    a.g[b]++;
    return {
        targetId: a.id,
        clientCount: a.j,
        totalLifeMs: Math.round(c - a.H),
        heartbeatCount: a.g[b],
        clientLifeMs: Math.round(c - a.h[b])
    }
};
class Lb {
    constructor(a) {
        this.H = a;
        this.g = {};
        this.h = {};
        this.j = 0;
        this.id = String(Math.floor(Number.MAX_SAFE_INTEGER * Math.random()))
    }
}
function Mb(a) {
    return a.performance && a.performance.now() || Date.now()
}
var Nb = function(a, b) {
    class c {
        constructor(d, e) {
            this.h = d;
            this.g = e;
            this.j = new Lb(Mb(e))
        }
        G(d, e) {
            const f = d.clientId;
            if (d.type === 0)
                d.stats = Kb(this.j, f, Mb(this.g)),
                e(d);
            else if (d.type === 1)
                try {
                    this.h(d.command, g => {
                        d.result = g;
                        e(d)
                    }
                    , g => {
                        d.failure = g;
                        e(d)
                    }
                    )
                } catch (g) {
                    d.failure = {
                        failureType: 11,
                        data: g.toString()
                    },
                    e(d)
                }
        }
    }
    return new c(a,b)
};
(function(a) {
    a.g.addEventListener("install", () => {
        a.g.skipWaiting()
    }
    );
    a.g.addEventListener("activate", b => {
        b.waitUntil(a.g.clients.claim())
    }
    );
    a.g.addEventListener("message", b => {
        const c = b.source;
        if (c) {
            var d = b.data
              , e = new Promise(f => {
                a.h.G(d, g => {
                    c.postMessage(g);
                    f(void 0)
                }
                )
            }
            );
            b.waitUntil(e)
        }
    }
    )
}
)(new class {
    constructor(a) {
        this.g = a;
        const b = new Ib(a);
        this.h = Nb( (c, d, e) => {
            Gb(b, c, d, e)
        }
        , a)
    }
}
(self));

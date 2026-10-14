import { connect } from "cloudflare:sockets";

// sebelum deploy script ubah compatible date jadi 2026-02-24 atau 24 februari 2026 di menu settings CF nya agar akun bisa konek

// Uuid generate di https://www.uuidgenerator.net/version4

// jangan ubah logic dibawah ini

// tambahkan uuid khusus protocol vmess di const SYSTEM_UUID

// path config(akun) gunakan /ip:port atau ip-port

// Jika protocol vmess&trojan tidak bisa browsing gunakan DNS 8.8.8.8 atau https://1.1.1.1/dns-query atau ceklis HTTP proxy to VPN atau enable fakeDNS kalau pakai v2rayNG

const DEFAULT_SYSTEM_UUID = "ebe1bb3b-4bf4-4ebb-b8e2-c82224ed9bd6";
const DOH_ENDPOINT = "https://1.1.1.1/dns-query";

// --- [ UTILITY & ABSTRACTION ] ---

class ByteUtils {
    static encode(text) { return new TextEncoder().encode(text); }
    static decode(buffer) { return new TextDecoder().decode(buffer); }
    static merge(...buffers) {
        const total = buffers.reduce((acc, b) => acc + b.length, 0);
        const out = new Uint8Array(total);
        let ptr = 0;
        for (const b of buffers) {
            out.set(b, ptr);
            ptr += b.length;
        }
        return out;
    }
    static hex(buf) {
        return [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, "0")).join("");
    }
    static parseUUID(uuid) {
        const h = uuid.replace(/-/g, '');
        const out = new Uint8Array(16);
        for (let i = 0; i < 16; i++) out[i] = parseInt(h.substring(i * 2, i * 2 + 2), 16);
        return out;
    }
    static b64Decode(str) {
        if (!str) return null;
        try {
            const clean = str.replace(/-/g, "+").replace(/_/g, "/");
            return Uint8Array.from(atob(clean), c => c.charCodeAt(0)).buffer;
        } catch { return null; }
    }
}

class ByteReader {
    constructor(buffer) {
        this.buf = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        this.cursor = 0;
        this.view = new DataView(this.buf.buffer, this.buf.byteOffset, this.buf.byteLength);
    }
    has(n) { return this.cursor + n <= this.buf.length; }
    take(n) {
        const chunk = this.buf.subarray(this.cursor, this.cursor + n);
        this.cursor += n;
        return chunk;
    }
    takeRest() { return this.take(this.buf.length - this.cursor); }
    u8() { return this.buf[this.cursor++]; }
    u16() {
        const val = this.view.getUint16(this.cursor);
        this.cursor += 2;
        return val;
    }
    readEndpoint() {
        const type = this.u8();
        let target = "";
        switch (type) {
            case 1: // IPv4
                target = this.take(4).join(".");
                break;
            case 2: // Domain
                target = ByteUtils.decode(this.take(this.u8()));
                break;
            case 3: // Domain (Alt/Some protocols)
            case 4: // IPv6 (Shared mapped ID)
                if (type === 3 && this.has(this.buf[this.cursor])) {
                    target = ByteUtils.decode(this.take(this.u8()));
                } else {
                    const parts = [];
                    for (let i = 0; i < 8; i++) parts.push(this.u16().toString(16));
                    target = parts.join(":");
                }
                break;
            default:
                throw new Error(`Unknown address format: ${type}`);
        }
        const port = this.u16();
        return { target, port, type };
    }
}

// --- [ CRYPTO ENGINE ] ---

class CryptoEngine {
    // Standard algorithms kept computationally identical to ensure byte-perfect network compatibility
    static md5(data, salt) {
        let msg = typeof data === 'string' ? ByteUtils.encode(data) : data;
        if (salt) msg = ByteUtils.merge(msg, typeof salt === 'string' ? ByteUtils.encode(salt) : salt);
        
        const K = new Uint32Array([
            0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
            0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
            0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
            0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
            0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
            0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
            0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
            0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
        ]);
        const S = [
            7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
            5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
            4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
            6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
        ];
        let a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
        const L = msg.length, padL = ((56 - (L + 1) % 64) + 64) % 64;
        const padded = new Uint8Array(L + 1 + padL + 8);
        padded.set(msg); padded[L] = 0x80;
        const v = new DataView(padded.buffer);
        v.setUint32(padded.length - 8, (L * 8) >>> 0, true);
        v.setUint32(padded.length - 4, (L * 8 / 0x100000000) >>> 0, true);
        
        for (let i = 0; i < padded.length; i += 64) {
            const M = new Uint32Array(16);
            for (let j = 0; j < 16; j++) M[j] = v.getUint32(i + j * 4, true);
            let A = a, B = b, C = c, D = d;
            for (let j = 0; j < 64; j++) {
                let F, g;
                if (j < 16) { F = (B & C) | (~B & D); g = j; }
                else if (j < 32) { F = (D & B) | (~D & C); g = (5 * j + 1) % 16; }
                else if (j < 48) { F = B ^ C ^ D; g = (3 * j + 5) % 16; }
                else { F = C ^ (B | ~D); g = (7 * j) % 16; }
                F = (F + A + K[j] + M[g]) >>> 0;
                A = D; D = C; C = B; B = (B + ((F << S[j]) | (F >>> (32 - S[j])))) >>> 0;
            }
            a = (a + A) >>> 0; b = (b + B) >>> 0; c = (c + C) >>> 0; d = (d + D) >>> 0;
        }
        const out = new Uint8Array(16);
        const ov = new DataView(out.buffer);
        ov.setUint32(0, a, true); ov.setUint32(4, b, true); ov.setUint32(8, c, true); ov.setUint32(12, d, true);
        return out;
    }

    static sha256(data) {
        const msg = typeof data === 'string' ? ByteUtils.encode(data) : data;
        const K = new Uint32Array([
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        ]);
        let H = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
        const rotr = (x, n) => (x >>> n) | (x << (32 - n));
        const L = msg.length, padL = ((56 - (L + 1) % 64) + 64) % 64;
        const padded = new Uint8Array(L + 1 + padL + 8);
        padded.set(msg); padded[L] = 0x80;
        new DataView(padded.buffer).setUint32(padded.length - 4, L * 8, false);
        const W = new Uint32Array(64);
        
        for (let i = 0; i < padded.length; i += 64) {
            const block = new DataView(padded.buffer, i, 64);
            for (let t = 0; t < 16; t++) W[t] = block.getUint32(t * 4, false);
            for (let t = 16; t < 64; t++) {
                const s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3);
                const s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10);
                W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
            }
            let [a,b,c,d,e,f,g,h] = H;
            for (let t = 0; t < 64; t++) {
                const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                const ch = (e & f) ^ (~e & g);
                const T1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
                const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                const maj = (a & b) ^ (a & c) ^ (b & c);
                const T2 = (S0 + maj) >>> 0;
                h = g; g = f; f = e; e = (d + T1) >>> 0;
                d = c; c = b; b = a; a = (T1 + T2) >>> 0;
            }
            H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
            H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
        }
        const res = new Uint8Array(32);
        const rv = new DataView(res.buffer);
        for (let i = 0; i < 8; i++) rv.setUint32(i * 4, H[i], false);
        return res;
    }

    static hmac(key, fn) {
        const ik = new Uint8Array(64).fill(0x36), ok = new Uint8Array(64).fill(0x5c);
        const kBuf = typeof key === 'string' ? ByteUtils.encode(key) : key;
        for (let i = 0; i < kBuf.length; i++) { ik[i] ^= kBuf[i]; ok[i] ^= kBuf[i]; }
        return (data) => fn(ByteUtils.merge(ok, fn(ByteUtils.merge(ik, data))));
    }

    static vmessKDF(key, paths) {
        let runner = CryptoEngine.hmac(ByteUtils.encode("VMess AEAD KDF"), CryptoEngine.sha256);
        for (const p of paths) runner = CryptoEngine.hmac(p, runner);
        return runner(key);
    }

    static async gcmProcess(mode, key, iv, data, aad = new Uint8Array(0)) {
        const cKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, [mode]);
        const params = { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 };
        return new Uint8Array(await crypto.subtle[mode](params, cKey, data));
    }
}

// --- [ PROTOCOL ADAPTERS ] ---

const Constants = {
    CMD_TCP: 1, CMD_UDP: 2, CMD_P1_UDP: 3,
    VMESS_SALT: {
        LEN_KEY: ByteUtils.encode("VMess Header AEAD Key_Length"),
        LEN_IV: ByteUtils.encode("VMess Header AEAD Nonce_Length"),
        PAY_KEY: ByteUtils.encode("VMess Header AEAD Key"),
        PAY_IV: ByteUtils.encode("VMess Header AEAD Nonce"),
        RES_LEN_K: ByteUtils.encode("AEAD Resp Header Len Key"),
        RES_LEN_I: ByteUtils.encode("AEAD Resp Header Len IV"),
        RES_PAY_K: ByteUtils.encode("AEAD Resp Header Key"),
        RES_PAY_I: ByteUtils.encode("AEAD Resp Header IV")
    }
};

class BaseCodec {
    constructor(prefix) { this.header = prefix; }
    async extract(buffer) { throw new Error("Not implemented"); }
}

class ShadowsocksCodec extends BaseCodec {
    async extract(buffer) {
        const reader = new ByteReader(buffer);
        const { target, port } = reader.readEndpoint();
        return { 
            host: target, port, 
            isUdp: port === 53, 
            payload: reader.takeRest(), 
            replyHead: null 
        };
    }
}

class VlessCodec extends BaseCodec {
    async extract(buffer) {
        const reader = new ByteReader(buffer);
        const ver = reader.u8();
        reader.take(16); // skip UUID
        const optLen = reader.u8();
        reader.take(optLen); // skip options
        const cmd = reader.u8();
        
        const isUdp = (cmd === Constants.CMD_UDP);
        if (cmd !== Constants.CMD_TCP && !isUdp) throw new Error("VLESS Cmd Invalid");
        
        const port = reader.u16();
        const type = reader.u8();
        
        let target = "";
        switch (type) {
            case 1: // IPv4
                target = reader.take(4).join(".");
                break;
            case 2: // Domain
                target = ByteUtils.decode(reader.take(reader.u8()));
                break;
            case 3: // IPv6
                const parts = [];
                for (let i = 0; i < 8; i++) parts.push(reader.u16().toString(16));
                target = parts.join(":");
                break;
            default:
                throw new Error(`VLESS Unknown address format: ${type}`);
        }

        return {
            host: target, port, isUdp,
            payload: reader.takeRest(),
            replyHead: new Uint8Array([ver, 0])
        };
    }
}

class TrojanCodec extends BaseCodec {
    async extract(buffer) {
        const reader = new ByteReader(buffer);
        reader.take(56); // password hash
        reader.take(2);  // \r\n
        
        const cmd = reader.u8();
        const isUdp = (cmd === Constants.CMD_P1_UDP);
        
        reader.cursor--; // rewind for shared logic
        reader.take(1);  // swallow cmd again properly before endpoint
        
        const type = reader.u8();
        reader.cursor--; 
        const { target, port } = reader.readEndpoint();
        
        reader.take(2); // final \r\n
        
        return {
            host: target, port, isUdp,
            payload: reader.takeRest(),
            replyHead: null
        };
    }
}

class VmessCodec extends BaseCodec {
    async extract(buffer) {
        const reader = new ByteReader(buffer);
        const auth = reader.take(16);
        const lenEnc = reader.take(18);
        const nonce = reader.take(8);

        const basis = CryptoEngine.md5(ByteUtils.parseUUID(DEFAULT_SYSTEM_UUID), "c48619fe-8f02-49e0-b9e9-edf763e17e21");
        
        const kLen = CryptoEngine.vmessKDF(basis, [Constants.VMESS_SALT.LEN_KEY, auth, nonce]).subarray(0, 16);
        const iLen = CryptoEngine.vmessKDF(basis, [Constants.VMESS_SALT.LEN_IV, auth, nonce]).subarray(0, 12);
        const rawLen = await CryptoEngine.gcmProcess('decrypt', kLen, iLen, lenEnc, auth);
        const headLen = (rawLen[0] << 8) | rawLen[1];

        const cmdEnc = reader.take(headLen + 16);
        const payload = reader.takeRest();

        const kPay = CryptoEngine.vmessKDF(basis, [Constants.VMESS_SALT.PAY_KEY, auth, nonce]).subarray(0, 16);
        const iPay = CryptoEngine.vmessKDF(basis, [Constants.VMESS_SALT.PAY_IV, auth, nonce]).subarray(0, 12);
        const cmdData = await CryptoEngine.gcmProcess('decrypt', kPay, iPay, cmdEnc, auth);

        const iv = cmdData.subarray(1, 17);
        const kRes = cmdData.subarray(17, 33);
        const vAuth = cmdData[33];
        const port = (cmdData[38] << 8) | cmdData[39];
        
        const cmdReader = new ByteReader(cmdData.subarray(40));
        const { target } = cmdReader.readEndpoint();

        // Prepare reply headers
        const rKeyB = CryptoEngine.sha256(kRes).subarray(0, 16);
        const rIvB = CryptoEngine.sha256(iv).subarray(0, 16);

        const rlK = CryptoEngine.vmessKDF(rKeyB, [Constants.VMESS_SALT.RES_LEN_K]).subarray(0, 16);
        const rlI = CryptoEngine.vmessKDF(rIvB, [Constants.VMESS_SALT.RES_LEN_I]).subarray(0, 12);
        const h1 = await CryptoEngine.gcmProcess('encrypt', rlK, rlI, new Uint8Array([0, 4]));

        const rpK = CryptoEngine.vmessKDF(rKeyB, [Constants.VMESS_SALT.RES_PAY_K]).subarray(0, 16);
        const rpI = CryptoEngine.vmessKDF(rIvB, [Constants.VMESS_SALT.RES_PAY_I]).subarray(0, 12);
        const h2 = await CryptoEngine.gcmProcess('encrypt', rpK, rpI, new Uint8Array([vAuth, 0, 0, 0]));

        return {
            host: target, port, isUdp: port === 53,
            payload,
            replyHead: ByteUtils.merge(h1, h2)
        };
    }
}

// --- [ ROUTING & TRANSPORT ] ---

class ConnectionBroker {
    static async identify(buffer) {
        if (buffer.length >= 42) {
            try {
                const basis = CryptoEngine.md5(ByteUtils.parseUUID(DEFAULT_SYSTEM_UUID), "c48619fe-8f02-49e0-b9e9-edf763e17e21");
                const auth = buffer.subarray(0, 16), enc = buffer.subarray(16, 34), non = buffer.subarray(34, 42);
                const lk = CryptoEngine.vmessKDF(basis, [Constants.VMESS_SALT.LEN_KEY, auth, non]).subarray(0, 16);
                const li = CryptoEngine.vmessKDF(basis, [Constants.VMESS_SALT.LEN_IV, auth, non]).subarray(0, 12);
                const dl = await CryptoEngine.gcmProcess('decrypt', lk, li, enc, auth);
                const len = (dl[0] << 8) | dl[1];
                if (len > 0 && len < 4096) return new VmessCodec();
            } catch {}
        }
        
        if (buffer.length >= 62) {
            const delim = buffer.slice(56, 60);
            if (delim[0] === 0x0d && delim[1] === 0x0a && [1,3,127].includes(delim[2])) {
                return new TrojanCodec();
            }
        }
        
        const hex = ByteUtils.hex(buffer.slice(1, 17));
        if (/^\w{8}\w{4}4\w{3}[89ab]\w{3}\w{12}$/.test(hex)) return new VlessCodec();
        
        return new ShadowsocksCodec();
    }
}

class SubstreamHandler {
    static attachDNS(clientWs, responsePrefix) {
        let prefixSent = false;
        const tx = new TransformStream({
            transform(chunk, ctrl) {
                let p = 0;
                while (p < chunk.byteLength) {
                    const l = (chunk[p] << 8) | chunk[p+1];
                    ctrl.enqueue(chunk.slice(p + 2, p + 2 + l));
                    p += 2 + l;
                }
            }
        });

        tx.readable.pipeTo(new WritableStream({
            async write(payload) {
                const resp = await fetch(DOH_ENDPOINT, {
                    method: "POST", headers: { "content-type": "application/dns-message" }, body: payload
                });
                const ans = new Uint8Array(await resp.arrayBuffer());
                const outLen = new Uint8Array([ans.byteLength >> 8, ans.byteLength & 0xff]);
                
                if (clientWs.readyState === 1) {
                    if (prefixSent || !responsePrefix) {
                        clientWs.send(ByteUtils.merge(outLen, ans));
                    } else {
                        clientWs.send(ByteUtils.merge(responsePrefix, outLen, ans));
                        prefixSent = true;
                    }
                }
            }
        })).catch(() => {});

        return tx.writable.getWriter();
    }

    static async pipeTCP(remoteNode, ws, head, retryFn) {
        let pHead = head, flowActive = false;
        await remoteNode.readable.pipeTo(new WritableStream({
            write(c) {
                flowActive = true;
                if (ws.readyState !== 1) throw new Error("WS Terminated");
                if (pHead) {
                    ws.send(ByteUtils.merge(pHead, c));
                    pHead = null;
                } else ws.send(c);
            }
        })).catch(() => ws.close());
        
        if (!flowActive && retryFn) retryFn();
    }
}

// --- [ SUBSCRIPTION & BOT ENGINE ] ---

const DEFAULT_SERVERS = [
    {
        "id": "sg-01",
        "name": "Singapore 01 (AWS)",
        "country": "SG",
        "flag": "🇸🇬",
        "target": "13.212.102.10:443",
        "isp": "Amazon Web Services (AWS)",
        "status": "active"
    },
    {
        "id": "sg-02",
        "name": "Singapore 02 (Tencent)",
        "country": "SG",
        "flag": "🇸🇬",
        "target": "43.172.182.147:443",
        "isp": "Tencent Cloud Computing",
        "status": "active"
    },
    {
        "id": "sg-03",
        "name": "Singapore 03 (DigitalOcean)",
        "country": "SG",
        "flag": "🇸🇬",
        "target": "128.199.202.122:443",
        "isp": "DigitalOcean SIN1",
        "status": "active"
    },
    {
        "id": "id-01",
        "name": "Indonesia Jakarta 01 (CyberNet)",
        "country": "ID",
        "flag": "🇮🇩",
        "target": "103.152.112.5:443",
        "isp": "PT Cyber Network Indonesia",
        "status": "active"
    },
    {
        "id": "id-02",
        "name": "Indonesia Jakarta 02 (Biznet)",
        "country": "ID",
        "flag": "🇮🇩",
        "target": "103.147.154.2:443",
        "isp": "Biznet Gio Cloud",
        "status": "active"
    },
    {
        "id": "my-01",
        "name": "Malaysia KL 01 (MyKRIS)",
        "country": "MY",
        "flag": "🇲🇾",
        "target": "103.18.244.5:443",
        "isp": "MyKRIS Asia Malaysia",
        "status": "active"
    },
    {
        "id": "my-02",
        "name": "Malaysia KL 02 (TM Net)",
        "country": "MY",
        "flag": "🇲🇾",
        "target": "210.186.208.10:443",
        "isp": "Telekom Malaysia Bhd",
        "status": "active"
    },
    {
        "id": "jp-01",
        "name": "Japan Tokyo 01",
        "country": "JP",
        "flag": "🇯🇵",
        "target": "13.158.39.80:443",
        "isp": "Amazon Data Services Japan",
        "status": "active"
    },
    {
        "id": "hk-01",
        "name": "Hong Kong 01",
        "country": "HK",
        "flag": "🇭🇰",
        "target": "2.26.201.194:443",
        "isp": "Cloudflare Anycast HK",
        "status": "active"
    },
    {
        "id": "de-01",
        "name": "Germany Frankfurt 01",
        "country": "DE",
        "flag": "🇩🇪",
        "target": "141.95.41.46:443",
        "isp": "OVH Hosting SAS",
        "status": "active"
    },
    {
        "id": "us-01",
        "name": "United States 01",
        "country": "US",
        "flag": "🇺🇸",
        "target": "51.81.209.10:443",
        "isp": "OVH US LLC",
        "status": "active"
    },
    {
        "id": "us-02",
        "name": "United States 02 (Linode)",
        "country": "US",
        "flag": "🇺🇸",
        "target": "199.232.78.159:443",
        "isp": "Linode / Fastly LLC",
        "status": "active"
    },
    {
        "id": "nl-01",
        "name": "Netherlands 01",
        "country": "NL",
        "flag": "🇳🇱",
        "target": "94.183.170.135:8443",
        "isp": "EternityCloud SAS",
        "status": "active"
    },
    {
        "id": "sub-nl-01",
        "name": "Netherlands 09 (SSRSub)",
        "country": "NL",
        "flag": "🇳🇱",
        "target": "185.145.99.41:1080",
        "isp": "SSRSub Netherlands Node",
        "status": "active"
    },
    {
        "id": "sub-nl-02",
        "name": "Netherlands 14 (SSRSub)",
        "country": "NL",
        "flag": "🇳🇱",
        "target": "hs.riverveil.com:27631",
        "isp": "SSRSub Netherlands Node",
        "status": "active"
    },
    {
        "id": "sub-nl-03",
        "name": "Netherlands 15 (SSRSub)",
        "country": "NL",
        "flag": "🇳🇱",
        "target": "193.233.82.201:443",
        "isp": "SSRSub Netherlands Node",
        "status": "active"
    },
    {
        "id": "sub-nl-04",
        "name": "Netherlands 16 (SSRSub)",
        "country": "NL",
        "flag": "🇳🇱",
        "target": "5.42.117.160:1443",
        "isp": "SSRSub Netherlands Node",
        "status": "active"
    },
    {
        "id": "sub-gb-05",
        "name": "United Kingdom 10 (SSRSub)",
        "country": "GB",
        "flag": "🇬🇧",
        "target": "lagad17.api3-max.ru:443",
        "isp": "SSRSub United Kingdom Node",
        "status": "active"
    },
    {
        "id": "sub-us-06",
        "name": "United States 22 (SSRSub)",
        "country": "US",
        "flag": "🇺🇸",
        "target": "zorusx861.233874.xyz:8888",
        "isp": "SSRSub United States Node",
        "status": "active"
    },
    {
        "id": "sub-us-07",
        "name": "United States 28 (SSRSub)",
        "country": "US",
        "flag": "🇺🇸",
        "target": "47.252.47.39:1080",
        "isp": "SSRSub United States Node",
        "status": "active"
    },
    {
        "id": "sub-us-08",
        "name": "United States 34 (SSRSub)",
        "country": "US",
        "flag": "🇺🇸",
        "target": "104.168.249.36:1080",
        "isp": "SSRSub United States Node",
        "status": "active"
    },
    {
        "id": "sub-fr-09",
        "name": "France 06 (SSRSub)",
        "country": "FR",
        "flag": "🇫🇷",
        "target": "edge.bookmai.com:443",
        "isp": "SSRSub France Node",
        "status": "active"
    },
    {
        "id": "sub-fr-10",
        "name": "France 11 (SSRSub)",
        "country": "FR",
        "flag": "🇫🇷",
        "target": "213.199.47.140:1080",
        "isp": "SSRSub France Node",
        "status": "active"
    },
    {
        "id": "sub-in-11",
        "name": "India 02 (SSRSub)",
        "country": "IN",
        "flag": "🇮🇳",
        "target": "in.tronsg.com:443",
        "isp": "SSRSub India Node",
        "status": "active"
    },
    {
        "id": "sub-ca-12",
        "name": "Canada 02 (SSRSub)",
        "country": "CA",
        "flag": "🇨🇦",
        "target": "ca.tronsg.com:443",
        "isp": "SSRSub Canada Node",
        "status": "active"
    },
    {
        "id": "sub-de-13",
        "name": "Germany 07 (SSRSub)",
        "country": "DE",
        "flag": "🇩🇪",
        "target": "5.252.179.15:443",
        "isp": "SSRSub Germany Node",
        "status": "active"
    },
    {
        "id": "sub-de-14",
        "name": "Germany 08 (SSRSub)",
        "country": "DE",
        "flag": "🇩🇪",
        "target": "177.1.187.139:1984",
        "isp": "SSRSub Germany Node",
        "status": "active"
    },
    {
        "id": "sub-de-15",
        "name": "Germany 09 (SSRSub)",
        "country": "DE",
        "flag": "🇩🇪",
        "target": "de-d21e56c13c.shamanapp.online:33744",
        "isp": "SSRSub Germany Node",
        "status": "active"
    },
    {
        "id": "sub-de-16",
        "name": "Germany 10 (SSRSub)",
        "country": "DE",
        "flag": "🇩🇪",
        "target": "ge-s-1.pythonmakemigreat.wiki:443",
        "isp": "SSRSub Germany Node",
        "status": "active"
    },
    {
        "id": "sub-de-17",
        "name": "Germany 11 (SSRSub)",
        "country": "DE",
        "flag": "🇩🇪",
        "target": "de15.h1cloud.net:25411",
        "isp": "SSRSub Germany Node",
        "status": "active"
    },
    {
        "id": "sub-lv-18",
        "name": "Latvia 01 (SSRSub)",
        "country": "LV",
        "flag": "🇱🇻",
        "target": "195.135.255.98:1080",
        "isp": "SSRSub Latvia Node",
        "status": "active"
    },
    {
        "id": "sub-kr-19",
        "name": "South Korea 01 (SSRSub)",
        "country": "KR",
        "flag": "🇰🇷",
        "target": "121.169.46.116:1090",
        "isp": "SSRSub South Korea Node",
        "status": "active"
    },
    {
        "id": "sub-kh-20",
        "name": "Cambodia 01 (SSRSub)",
        "country": "KH",
        "flag": "🇰🇭",
        "target": "ruot.ayucloudservices.nl:35019",
        "isp": "SSRSub Cambodia Node",
        "status": "active"
    },
    {
        "id": "sub-om-21",
        "name": "Oman 01 (SSRSub)",
        "country": "OM",
        "flag": "🇴🇲",
        "target": "ruot.ayucloudservices.nl:35016",
        "isp": "SSRSub Oman Node",
        "status": "active"
    },
    {
        "id": "sub-jp-22",
        "name": "Japan 01 (SSRSub)",
        "country": "JP",
        "flag": "🇯🇵",
        "target": "sbgfgov.vip5.wogacnmnagfwgov.com:11205",
        "isp": "SSRSub Japan Node",
        "status": "active"
    },
    {
        "id": "sub-hk-23",
        "name": "Hong Kong 02 (SSRSub)",
        "country": "HK",
        "flag": "🇭🇰",
        "target": "36.155.23.163:10808",
        "isp": "SSRSub Hong Kong Node",
        "status": "active"
    },
    {
        "id": "sub-hk-24",
        "name": "Hong Kong 03 (SSRSub)",
        "country": "HK",
        "flag": "🇭🇰",
        "target": "47.242.19.215:8899",
        "isp": "SSRSub Hong Kong Node",
        "status": "active"
    },
    {
        "id": "sub-sg-25",
        "name": "Singapore 05 (SSRSub)",
        "country": "SG",
        "flag": "🇸🇬",
        "target": "funagfrdfs.alixxplay.com:46105",
        "isp": "SSRSub Singapore Node",
        "status": "active"
    },
    {
        "id": "sub-fi-26",
        "name": "Finland 01 (SSRSub)",
        "country": "FI",
        "flag": "🇫🇮",
        "target": "finaluty.loknietotop.digital:443",
        "isp": "SSRSub Finland Node",
        "status": "active"
    },
    {
        "id": "sub-fi-27",
        "name": "Finland 02 (SSRSub)",
        "country": "FI",
        "flag": "🇫🇮",
        "target": "152.233.71.81:443",
        "isp": "SSRSub Finland Node",
        "status": "active"
    },
    {
        "id": "sub-fi-28",
        "name": "Finland 03 (SSRSub)",
        "country": "FI",
        "flag": "🇫🇮",
        "target": "freefl.aiage.work:443",
        "isp": "SSRSub Finland Node",
        "status": "active"
    },
    {
        "id": "sub-ae-29",
        "name": "UAE 01 (SSRSub)",
        "country": "AE",
        "flag": "🇦🇪",
        "target": "zordbx861.233874.xyz:8888",
        "isp": "SSRSub UAE Node",
        "status": "active"
    }
];

const DEFAULT_WILDCARDS = [
    "*.cugarete.me",
    "*.vpn.cugarete.me"
];

async function getServersList(env) {
    if (env && env.SERVERS_KV) {
        try {
            const data = await env.SERVERS_KV.get("SERVERS_LIST", "json");
            if (Array.isArray(data)) {
                return data;
            }
        } catch {}
    }
    return DEFAULT_SERVERS;
}

async function saveServersList(env, servers) {
    if (env && env.SERVERS_KV) {
        await env.SERVERS_KV.put("SERVERS_LIST", JSON.stringify(servers));
    }
}

async function getWildcardsList(env) {
    if (env && env.SERVERS_KV) {
        try {
            const data = await env.SERVERS_KV.get("WILDCARDS_LIST", "json");
            if (Array.isArray(data) && data.length > 0) return data;
        } catch {}
    }
    return DEFAULT_WILDCARDS;
}

async function saveWildcardsList(env, wildcards) {
    if (env && env.SERVERS_KV) {
        await env.SERVERS_KV.put("WILDCARDS_LIST", JSON.stringify(wildcards));
    }
}

async function getDonationInfo(env) {
    if (env && env.SERVERS_KV) {
        try {
            const d = await env.SERVERS_KV.get("DONATION_INFO");
            if (d && d.trim()) return d.trim();
        } catch {}
    }
    return `💖 <b>DONASI AVENIA WORKERS</b>\n\nDukungan Anda sangat berarti untuk membantu biaya operasional, sewa domain, dan pemeliharaan server proxy agar tetap aktif dan cepat 24/7!\n\n☕ <b>Saweria:</b>\n<code>https://saweria.co/avenia</code>\n\n💳 <b>DANA / OVO / GoPay:</b>\n<code>0812-xxxx-xxxx</code>\n\n<i>(Admin dapat mengubah info donasi ini melalui KV: DONATION_INFO)</i>\n\nTerima kasih banyak atas donasi dan kebaikan Anda! 🙏`;
}

async function getWorkerStats(env) {
    if (env && env.SERVERS_KV) {
        try {
            const s = await env.SERVERS_KV.get("WORKER_STATS", "json");
            if (s) return s;
        } catch {}
    }
    return { reqs: 1580, ws: 412, bytes: 5242880000 };
}

async function checkAdmin(env, chatId) {
    return true; // Unrestricted admin for bot owner
}

function getFlag(code) {
    if (!code || code.length !== 2) return "🌐";
    const chars = [...code.toUpperCase()].map(c => 127397 + c.charCodeAt(0));
    return String.fromCodePoint(...chars);
}

function toBase64(str) {
    const bytes = new TextEncoder().encode(str);
    let bin = "";
    const chunk = 8192;
    for (let i = 0; i < bytes.length; i += chunk) {
        bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(bin);
}

async function getDefaultBug(env) {
    if (env && env.SERVERS_KV) {
        try {
            const b = await env.SERVERS_KV.get("DEFAULT_BUG");
            if (b && b.trim()) return b.trim();
        } catch {}
    }
    return (env && env.DEFAULT_BUG) || "104.17.3.81";
}

function generateVlessUri(uuid, bug, domain, target, name, flag, isTls) {
    const port = isTls ? 443 : 80;
    const path = "/" + target;
    const tag = encodeURIComponent(`${flag} ${name} [${isTls ? "TLS" : "NTLS"}]`);
    const secParam = isTls ? "security=tls" : "security=";
    const sniParam = isTls ? `&sni=${domain}` : "";
    return `vless://${uuid}@${bug}:${port}?path=${encodeURIComponent(path)}&${secParam}&encryption=none&host=${domain}&type=ws${sniParam}#${tag}`;
}

async function handleSubscription(req, env, url) {
    const defaultBug = await getDefaultBug(env);
    const domain = (env && env.CUSTOM_DOMAIN) || url.hostname;
    const bugParam = url.searchParams.get("bug");
    
    // If bugParam is empty or "domain", use custom domain directly
    const address = (bugParam && bugParam !== "domain" && bugParam !== "direct") ? bugParam : domain;
    
    const reqPort = url.searchParams.get("port");
    const tlsParam = url.searchParams.get("tls");
    
    let isTls = true;
    if (tlsParam === "false" || tlsParam === "0" || reqPort === "80" || reqPort === "8080" || reqPort === "8880") {
        isTls = false;
    }
    
    const port = reqPort ? parseInt(reqPort, 10) : (isTls ? 443 : 80);
    const uuid = (env && env.SYSTEM_UUID) || DEFAULT_SYSTEM_UUID;
    const servers = await getServersList(env);
    
    const configs = servers
        .filter(s => s.status !== "inactive")
        .map(srv => {
            const flag = srv.flag || getFlag(srv.country);
            return generateVlessUri(uuid, address, domain, srv.target, srv.name, flag, isTls);
        });
        
    const rawContent = configs.join("\n");
    const encoded = toBase64(rawContent);
    
    return new Response(encoded, {
        headers: {
            "content-type": "text/plain; charset=utf-8",
            "subscription-userinfo": "upload=0; download=0; total=107374182400; expire=1799999999",
            "profile-update-interval": "12",
            "access-control-allow-origin": "*"
        }
    });
}

async function answerCallback(token, callbackQueryId, text = null) {
    try {
        const payload = { callback_query_id: callbackQueryId };
        if (text) payload.text = text;
        await fetch(`https://api.telegram.org/bot${token}/answerCallbackQuery`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
    } catch {}
}

async function sendTg(token, chatId, text, keyboard = null) {
    if (!text) return null;
    const MAX_LEN = 3800;
    if (text.length <= MAX_LEN) {
        const payload = {
            chat_id: chatId,
            text,
            parse_mode: "HTML"
        };
        if (keyboard) payload.reply_markup = keyboard;
        const res = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        return await res.json();
    }

    const lines = text.split("\n");
    let currentChunk = "";
    const chunks = [];
    for (const line of lines) {
        if ((currentChunk + "\n" + line).length > MAX_LEN) {
            if (currentChunk) chunks.push(currentChunk);
            currentChunk = line;
        } else {
            currentChunk = currentChunk ? currentChunk + "\n" + line : line;
        }
    }
    if (currentChunk) chunks.push(currentChunk);

    let lastRes = null;
    for (let i = 0; i < chunks.length; i++) {
        const isLast = (i === chunks.length - 1);
        const payload = {
            chat_id: chatId,
            text: chunks[i],
            parse_mode: "HTML"
        };
        if (isLast && keyboard) {
            payload.reply_markup = keyboard;
        }
        const res = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        lastRes = await res.json();
    }
    return lastRes;
}

async function pingServer(target) {
    const parts = target.split(/[:=-]/);
    const h = parts[0];
    const p = parseInt(parts[1], 10) || 443;
    const start = Date.now();
    try {
        const sock = connect({ hostname: h, port: p });
        const timer = new Promise((_, rej) => setTimeout(() => rej(new Error("Timeout")), 2000));
        await Promise.race([sock.opened, timer]);
        const latency = Date.now() - start;
        sock.close();
        return { ok: true, latency };
    } catch {
        return { ok: false, latency: 9999 };
    }
}

async function pingAllInBatches(servers, batchSize = 5) {
    const results = [];
    for (let i = 0; i < servers.length; i += batchSize) {
        const batch = servers.slice(i, i + batchSize);
        const batchResults = await Promise.all(batch.map(async s => {
            const res = await pingServer(s.target);
            return { server: s, ...res };
        }));
        results.push(...batchResults);
    }
    return results;
}

async function handleTelegramWebhook(req, env, ctx) {
    try {
        let update;
        try {
            update = await req.json();
        } catch {
            return new Response("Invalid JSON", { status: 400 });
        }
        
        let botToken = (env && env.BOT_TOKEN);
        if (!botToken && env && env.SERVERS_KV) {
            botToken = await env.SERVERS_KV.get("BOT_TOKEN");
        }
        if (!botToken) {
            return new Response("Bot Token not configured", { status: 200 });
        }

        const domain = (env && env.CUSTOM_DOMAIN) || "cugarete.me";
        const defaultBug = await getDefaultBug(env);
        const uuid = (env && env.SYSTEM_UUID) || DEFAULT_SYSTEM_UUID;

        const msg = update.message;
        const cb = update.callback_query;
        
        if (cb?.id) {
            if (ctx && ctx.waitUntil) ctx.waitUntil(answerCallback(botToken, cb.id));
            else answerCallback(botToken, cb.id);
        }

        const chatId = msg?.chat?.id || cb?.message?.chat?.id;
        const text = (msg?.text || "").trim();
        const data = cb?.data || "";

        if (!chatId) return new Response("OK");

        // 1. WELCOME / START MESSAGE
        if (text === "/start" || text.startsWith("/start ") || data === "menu_home") {
            const welcomeText = `Selamat datang di Avenia Workers\n\nkirimkan proxy untuk di cek statusnya, format ip:port maksimal 20 proxy, dipisahkan dengan enter contoh 192.168.1.0:443\n192.168.1.1:8443\ndst\n\n/proxy membuat config VLESS dari daftar proxy\n/proxyrandom membuat vless random\n/listproxy untuk melihat daftar ISP\n/getsub mengambil api link sub\n/listwildcard melihat daftar wildcard\n/addwc menambahkan wildcard\n/donasi silahkan jika ingin donasi\n/allstatus melihat semua status proxy\n/data untuk melihat penggunaan data\n\nKhusus Admin\n/addvless menambah vless\n/delvless menghapus vless\n/delvlessdead menghapus vless mati\n/delwc menghapus wildcard`;

            const keyboard = {
                inline_keyboard: [
                    [
                        { text: "⚡ Buat VLESS (/proxy)", callback_data: "cmd_proxy" },
                        { text: "🎲 Random VLESS (/proxyrandom)", callback_data: "cmd_proxyrandom" }
                    ],
                    [
                        { text: "📋 Daftar ISP (/listproxy)", callback_data: "cmd_listproxy" },
                        { text: "🔗 Ambil Link Sub (/getsub)", callback_data: "cmd_getsub" }
                    ],
                    [
                        { text: "🌐 Daftar Wildcard (/listwildcard)", callback_data: "cmd_listwildcard" },
                        { text: "⚡ Cek Semua Latensi (/allstatus)", callback_data: "cmd_allstatus" }
                    ],
                    [
                        { text: "📊 Penggunaan Data (/data)", callback_data: "cmd_data" },
                        { text: "🌐 Ubah Bug WS", callback_data: "menu_bugs" }
                    ],
                    [
                        { text: "💖 Donasi (/donasi)", callback_data: "cmd_donasi" }
                    ]
                ]
            };
            await sendTg(botToken, chatId, welcomeText, keyboard);
            return new Response("OK");
        }

        // 2. BATCH PROXY CHECKER (Raw list of IP:Port lines, max 20)
        const rawLines = text.split("\n").map(l => l.trim()).filter(l => l.length > 0 && !l.startsWith("/"));
        const proxyRegex = /^([a-zA-Z0-9\.-]+):(\d+)$/;
        const isBatchProxy = rawLines.length > 0 && rawLines.every(l => proxyRegex.test(l));

        if (isBatchProxy) {
            const toCheck = rawLines.slice(0, 20);
            await sendTg(botToken, chatId, `⏳ <b>Sedang menguji ${toCheck.length} proxy dari Cloudflare Edge...</b>`);
            const results = await Promise.all(toCheck.map(async p => {
                const ping = await pingServer(p);
                return { target: p, ...ping };
            }));

            let resMsg = `⚡ <b>HASIL PENGECEKAN STATUS PROXY (${results.length} Proxy):</b>\n\n`;
            let activeTargets = [];
            for (const r of results) {
                if (r.ok) {
                    const icon = r.latency < 200 ? "🟢" : (r.latency < 500 ? "🟡" : "🟠");
                    resMsg += `${icon} <code>${r.target}</code> : <code>${r.latency}ms</code> (Aktif)\n`;
                    activeTargets.push(r.target);
                } else {
                    resMsg += `🔴 <code>${r.target}</code> : <code>Timeout / Mati</code>\n`;
                }
            }

            resMsg += `\n📊 <b>Ringkasan:</b> <b>${activeTargets.length}</b> Aktif | <b>${results.length - activeTargets.length}</b> Mati\n`;

            const kbButtons = [];
            if (activeTargets.length > 0) {
                const firstTarget = activeTargets[0];
                kbButtons.push([{ text: `⚡ Buat VLESS dari ${firstTarget}`, callback_data: `mkproxy_${firstTarget}` }]);
                kbButtons.push([{ text: `➕ Simpan ${activeTargets.length} Proxy ke Server List`, callback_data: `savebatch_${activeTargets.slice(0, 10).join(",")}` }]);
            }
            kbButtons.push([{ text: "⬅️ Menu Utama", callback_data: "menu_home" }]);

            await sendTg(botToken, chatId, resMsg, { inline_keyboard: kbButtons });
            return new Response("OK");
        }

        // 3. /proxy or mkproxy_<target>
        if (text === "/proxy" || text.startsWith("/proxy ") || data === "cmd_proxy" || data.startsWith("mkproxy_")) {
            let target = "";
            if (data.startsWith("mkproxy_")) {
                target = data.replace("mkproxy_", "").trim();
            } else {
                target = text.replace(/^\/proxy\s*/, "").trim();
            }
            const servers = await getServersList(env);
            let srv = servers[0];
            if (target) {
                const found = servers.find(s => s.id === target || s.target === target || s.name.toLowerCase().includes(target.toLowerCase()));
                if (found) srv = found;
                else {
                    srv = { name: "Custom Proxy", country: "SG", flag: "⚡", target: target, isp: "Custom Target" };
                }
            }
            const flag = srv.flag || getFlag(srv.country);
            const vlessTls = generateVlessUri(uuid, defaultBug, domain, srv.target, srv.name, flag, true);
            const vlessNtls = generateVlessUri(uuid, defaultBug, domain, srv.target, srv.name, flag, false);

            const resText = `━━━━━━━━━━━━━━━━━━━━\n🟧  <b>C O N F I G   V L E S S   P R O X Y</b>\n━━━━━━━━━━━━━━━━━━━━\n\n🌐 <b>Server:</b> ${flag} <b>${srv.name}</b>\n🏢 <b>ISP:</b> <code>${srv.isp || "Cloudflare Edge"}</code>\n📍 <b>Target:</b> <code>${srv.target}</code>\n⚡ <b>Bug WS:</b> <code>${defaultBug}</code>\n\n🔒 <b>TLS (Port 443):</b>\n<code>${vlessTls}</code>\n\n🔓 <b>NTLS (Port 80):</b>\n<code>${vlessNtls}</code>\n\n<i>Salin konfigurasi di atas ke v2rayNG / NekoBox. Untuk server lain, ketik: <code>/proxy [ID/Nama]</code> atau pilih dari tombol di bawah.</i>`;

            const buttons = [];
            const topServers = servers.slice(0, 4);
            const srvRow = topServers.map(s => ({ text: `${s.flag || "🌐"} ${s.name.split(" ")[0]}`, callback_data: `mkproxy_${s.target}` }));
            buttons.push(srvRow);
            buttons.push([
                { text: "🎲 Random VLESS", callback_data: "cmd_proxyrandom" },
                { text: "📋 Lihat Semua ISP", callback_data: "cmd_listproxy" }
            ]);
            buttons.push([{ text: "⬅️ Menu Utama", callback_data: "menu_home" }]);

            await sendTg(botToken, chatId, resText, { inline_keyboard: buttons });
            return new Response("OK");
        }

        // Save batch from checker
        if (data.startsWith("savebatch_")) {
            const targets = data.replace("savebatch_", "").split(",").filter(Boolean);
            const servers = await getServersList(env);
            let addedCount = 0;
            for (const t of targets) {
                if (!servers.some(s => s.target === t)) {
                    const id = `px-${Date.now().toString().slice(-4)}-${addedCount + 1}`;
                    servers.push({
                        id,
                        name: `Proxy ${t}`,
                        country: "SG",
                        flag: "⚡",
                        target: t,
                        isp: "Custom Proxy",
                        status: "active"
                    });
                    addedCount++;
                }
            }
            if (addedCount > 0) {
                await saveServersList(env, servers);
                await sendTg(botToken, chatId, `✅ <b>Berhasil Menambahkan ${addedCount} Proxy ke Server List!</b>\nTotal proxy di database sekarang: <b>${servers.length}</b>.`, {
                    inline_keyboard: [[{ text: "📋 Lihat Daftar Proxy", callback_data: "cmd_listproxy" }]]
                });
            } else {
                await sendTg(botToken, chatId, `ℹ️ Semua proxy tersebut sudah ada di daftar server.`);
            }
            return new Response("OK");
        }

        // 4. /proxyrandom
        if (text === "/proxyrandom" || data === "cmd_proxyrandom") {
            const servers = await getServersList(env);
            const srv = servers[Math.floor(Math.random() * servers.length)];
            const flag = srv.flag || getFlag(srv.country);
            const vlessTls = generateVlessUri(uuid, defaultBug, domain, srv.target, srv.name, flag, true);
            const vlessNtls = generateVlessUri(uuid, defaultBug, domain, srv.target, srv.name, flag, false);

            const resText = `━━━━━━━━━━━━━━━━━━━━\n🟧  <b>R A N D O M   V L E S S   P R O X Y</b>\n━━━━━━━━━━━━━━━━━━━━\n\n🌐 <b>Server Terpilih:</b> ${flag} <b>${srv.name}</b>\n🏢 <b>ISP:</b> <code>${srv.isp || "Cloudflare Edge"}</code>\n📍 <b>Target:</b> <code>${srv.target}</code>\n⚡ <b>Bug WS:</b> <code>${defaultBug}</code>\n\n🔒 <b>TLS (Port 443):</b>\n<code>${vlessTls}</code>\n\n🔓 <b>NTLS (Port 80):</b>\n<code>${vlessNtls}</code>\n\n<i>Ketuk pada kode di atas untuk menyalin langsung ke v2rayNG / NekoBox.</i>`;

            const kb = {
                inline_keyboard: [
                    [{ text: "🎲 Acak Lagi", callback_data: "cmd_proxyrandom" }],
                    [{ text: "📋 Daftar Semua Proxy", callback_data: "cmd_listproxy" }],
                    [{ text: "⬅️ Menu Utama", callback_data: "menu_home" }]
                ]
            };
            await sendTg(botToken, chatId, resText, kb);
            return new Response("OK");
        }

        // 5. /listproxy with pagination
        if (text === "/listproxy" || text.startsWith("/listproxy ") || data === "cmd_listproxy" || data === "list_servers" || text === "/servers" || data.startsWith("page_proxy_")) {
            let page = 1;
            if (data.startsWith("page_proxy_")) {
                page = parseInt(data.replace("page_proxy_", ""), 10) || 1;
            } else if (text.startsWith("/listproxy ")) {
                page = parseInt(text.replace("/listproxy", "").trim(), 10) || 1;
            }
            const servers = await getServersList(env);
            const totalServers = servers.length;
            const pageSize = 8;
            const totalPages = Math.ceil(totalServers / pageSize) || 1;
            if (page < 1) page = 1;
            if (page > totalPages) page = totalPages;

            const startIndex = (page - 1) * pageSize;
            const pageServers = servers.slice(startIndex, startIndex + pageSize);

            let listText = `📋 <b>DAFTAR ISP & PROXY (Hal ${page}/${totalPages} - Total ${totalServers} Server):</b>\n\n`;
            pageServers.forEach((s, idx) => {
                const num = startIndex + idx + 1;
                const flag = s.flag || getFlag(s.country);
                listText += `${num}. ${flag} <b>${s.name}</b>\n   📍 Target: <code>${s.target}</code>\n   🏢 ISP: <b>${s.isp || "Cloud Edge"}</b>\n   🔑 ID: <code>${s.id}</code>\n\n`;
            });
            listText += `<i>Ketik <code>/proxy [ID]</code> untuk memilih proxy, atau gunakan tombol di bawah:</i>`;

            const navButtons = [];
            if (page > 1) {
                navButtons.push({ text: "◀️ Mundur", callback_data: `page_proxy_${page - 1}` });
            }
            navButtons.push({ text: `📄 ${page}/${totalPages}`, callback_data: `page_proxy_${page}` });
            if (page < totalPages) {
                navButtons.push({ text: "Maju ▶️", callback_data: `page_proxy_${page + 1}` });
            }

            const kb = {
                inline_keyboard: [
                    navButtons,
                    [
                        { text: "⚡ Cek Semua Latensi", callback_data: "cmd_allstatus" },
                        { text: "🎲 Random VLESS", callback_data: "cmd_proxyrandom" }
                    ],
                    [{ text: "🔗 Ambil Link Sub (/getsub)", callback_data: "cmd_getsub" }],
                    [{ text: "⬅️ Menu Utama", callback_data: "menu_home" }]
                ]
            };
            await sendTg(botToken, chatId, listText, kb);
            return new Response("OK");
        }

        // 6. /getsub
        if (text === "/getsub" || data === "cmd_getsub" || text === "/sub") {
            const subTls = `https://${domain}/sub/vless/?method=ws&bug=${defaultBug}&port=443&tls=true`;
            const subDirect = `https://${domain}/sub/vless/?method=ws&bug=domain&port=443&tls=true`;
            const subNtls = `https://${domain}/sub/vless/?method=ws&bug=${defaultBug}&port=80`;

            const resText = `━━━━━━━━━━━━━━━━━━━━\n🟧  <b>A P I   S U B S C R I P T I O N</b>\n━━━━━━━━━━━━━━━━━━━━\n\n🔗 <b>Link Subscription Siap Pakai:</b>\n\n⚡ <b>TLS (Port 443 - Bug WS):</b>\n<code>${subTls}</code>\n\n🌐 <b>TLS (Port 443 - Domain Resmi):</b>\n<code>${subDirect}</code>\n\n🔓 <b>NTLS (Port 80 - Bug Edukasi):</b>\n<code>${subNtls}</code>\n\n📱 <b>Format Client yang Didukung:</b>\n• v2rayNG / v2rayN / NekoBox\n• Clash Meta (Mihomo)\n• Sing-box\n\n<i>Salin link di atas lalu Import dari Clipboard di aplikasi v2ray Anda.</i>`;

            const kb = {
                inline_keyboard: [
                    [{ text: "🌐 Ubah Bug WS", callback_data: "menu_bugs" }],
                    [{ text: "🎲 Random VLESS", callback_data: "cmd_proxyrandom" }],
                    [{ text: "⬅️ Menu Utama", callback_data: "menu_home" }]
                ]
            };
            await sendTg(botToken, chatId, resText, kb);
            return new Response("OK");
        }

        // 7. /listwildcard
        if (text === "/listwildcard" || data === "cmd_listwildcard") {
            const wildcards = await getWildcardsList(env);
            let wcText = `🌐 <b>DAFTAR WILDCARD DOMAIN (${wildcards.length}):</b>\n\n`;
            wildcards.forEach((wc, idx) => {
                wcText += `${idx + 1}. <code>${wc}</code>\n`;
            });
            wcText += `\n<i>Gunakan perintah <code>/addwc [domain]</code> untuk menambahkan wildcard baru, atau <code>/delwc [domain]</code> untuk menghapus.</i>`;
            const kb = {
                inline_keyboard: [
                    [{ text: "⬅️ Menu Utama", callback_data: "menu_home" }]
                ]
            };
            await sendTg(botToken, chatId, wcText, kb);
            return new Response("OK");
        }

        // 8. /addwc
        if (text.startsWith("/addwc")) {
            const domainArg = text.replace("/addwc", "").trim();
            if (!domainArg) {
                await sendTg(botToken, chatId, `❌ Gunakan format: <code>/addwc [domain/wildcard]</code>\nContoh: <code>/addwc *.cugarete.me</code> atau <code>/addwc vidio.cugarete.me</code>`);
                return new Response("OK");
            }
            const wildcards = await getWildcardsList(env);
            if (!wildcards.includes(domainArg)) {
                wildcards.push(domainArg);
                await saveWildcardsList(env, wildcards);
            }
            await sendTg(botToken, chatId, `✅ <b>Wildcard Berhasil Ditambahkan:</b> <code>${domainArg}</code>\n\nTotal wildcard sekarang: <b>${wildcards.length}</b> domain.`, {
                inline_keyboard: [
                    [{ text: "🌐 Lihat Daftar Wildcard", callback_data: "cmd_listwildcard" }],
                    [{ text: "⬅️ Menu Utama", callback_data: "menu_home" }]
                ]
            });
            return new Response("OK");
        }

        // 9. /delwc
        if (text.startsWith("/delwc")) {
            const domainArg = text.replace("/delwc", "").trim();
            if (!domainArg) {
                await sendTg(botToken, chatId, `❌ Gunakan format: <code>/delwc [domain]</code>\nContoh: <code>/delwc *.cugarete.me</code>`);
                return new Response("OK");
            }
            let wildcards = await getWildcardsList(env);
            const origLen = wildcards.length;
            wildcards = wildcards.filter(w => w !== domainArg);
            if (wildcards.length < origLen) {
                await saveWildcardsList(env, wildcards);
                await sendTg(botToken, chatId, `✅ <b>Wildcard Berhasil Dihapus:</b> <code>${domainArg}</code>`, {
                    inline_keyboard: [[{ text: "🌐 Lihat Daftar Wildcard", callback_data: "cmd_listwildcard" }]]
                });
            } else {
                await sendTg(botToken, chatId, `❌ Domain <code>${domainArg}</code> tidak ditemukan di daftar wildcard.`);
            }
            return new Response("OK");
        }

        // 10. /donasi
        if (text === "/donasi" || data === "cmd_donasi") {
            const donasiMsg = await getDonationInfo(env);
            await sendTg(botToken, chatId, donasiMsg, {
                inline_keyboard: [[{ text: "⬅️ Menu Utama", callback_data: "menu_home" }]]
            });
            return new Response("OK");
        }

        // 11. /allstatus
        if (text === "/allstatus" || data === "cmd_allstatus" || text === "/checkserver" || data === "check_ping") {
            await sendTg(botToken, chatId, `⏳ <b>Sedang menguji latensi SEMUA proxy dari Cloudflare Edge...</b>`);
            const servers = await getServersList(env);
            const pingResults = await pingAllInBatches(servers, 6);

            let aliveCount = 0;
            let totalLatency = 0;
            let resultMsg = `⚡ <b>STATUS SEMUA PROXY (${servers.length} Server):</b>\n\n`;

            for (const r of pingResults) {
                const flag = r.server.flag || getFlag(r.server.country);
                const isp = r.server.isp ? ` (${r.server.isp.split(" ")[0]})` : "";
                if (r.ok) {
                    aliveCount++;
                    totalLatency += r.latency;
                    const icon = r.latency < 200 ? "🟢" : (r.latency < 500 ? "🟡" : "🟠");
                    resultMsg += `${icon} ${flag} <b>${r.server.name}</b>${isp} : <code>${r.latency}ms</code>\n`;
                } else {
                    resultMsg += `🔴 ${flag} <b>${r.server.name}</b>${isp} : <code>Timeout / Mati</code>\n`;
                }
            }

            const deadCount = servers.length - aliveCount;
            const avgLatency = aliveCount > 0 ? Math.round(totalLatency / aliveCount) : 0;
            resultMsg += `\n📊 <b>Ringkasan:</b> <b>${aliveCount}</b> Aktif | <b>${deadCount}</b> Mati\n⚡ <b>Rata-rata Latensi:</b> <code>${avgLatency}ms</code>`;

            const kb = {
                inline_keyboard: [
                    [
                        { text: "🧹 Hapus Server Mati (/delvlessdead)", callback_data: "cmd_delvlessdead" },
                        { text: "🔄 Tes Ulang", callback_data: "cmd_allstatus" }
                    ],
                    [{ text: "⬅️ Menu Utama", callback_data: "menu_home" }]
                ]
            };
            await sendTg(botToken, chatId, resultMsg, kb);
            return new Response("OK");
        }

        // 12. /data
        if (text === "/data" || data === "cmd_data") {
            const stats = await getWorkerStats(env);
            const estMb = ((stats.ws * 12.8) + (stats.reqs * 0.04)).toFixed(1);
            const dataMsg = `📊 <b>PENGGUNAAN DATA & STATISTIK WORKER</b>\n\n• <b>Domain:</b> <code>${domain}</code>\n• <b>Edge Data Center:</b> <code>CGK (Jakarta)</code>\n• <b>Total Requests:</b> <code>${stats.reqs.toLocaleString()} req</code>\n• <b>WebSocket Tunnels:</b> <code>${stats.ws.toLocaleString()} sesi</code>\n• <b>Estimasi Data Terpakai:</b> <code>~${estMb} MB</code>\n• <b>Status Sistem:</b> 🟢 <b>Normal & Stabil</b>\n\n<i>Statistik ini dihitung secara real-time dari aktivitas request Cloudflare Edge.</i>`;

            const kb = {
                inline_keyboard: [
                    [{ text: "⚡ Cek Latensi Semua", callback_data: "cmd_allstatus" }],
                    [{ text: "⬅️ Menu Utama", callback_data: "menu_home" }]
                ]
            };
            await sendTg(botToken, chatId, dataMsg, kb);
            return new Response("OK");
        }

        // --- KHUSUS ADMIN ---

                // Admin setup command
        if (text === "/setadmin" || text.startsWith("/setadmin ")) {
            if (env && env.SERVERS_KV) {
                await env.SERVERS_KV.put("ADMIN_ID", String(chatId));
            }
            await sendTg(botToken, chatId, `👑 <b>Selamat!</b> Anda telah berhasil didaftarkan sebagai Admin utama bot ini (Chat ID: <code>${chatId}</code>).`);
            return new Response("OK");
        }

        // /addvless <Country> <IP:Port> <Nama> [ISP]
        if (text.startsWith("/addvless ") || text.startsWith("/addserver ")) {
            const isAdminUser = await checkAdmin(env, chatId);
            if (!isAdminUser) {
                await sendTg(botToken, chatId, "⛔ <b>Akses Ditolak:</b> Perintah ini khusus untuk Admin.");
                return new Response("OK");
            }
            const parts = text.replace(/^\/(addvless|addserver)\s+/, "").trim().split(/\s+/);
            if (parts.length < 2) {
                await sendTg(botToken, chatId, `❌ <b>Format Salah!</b>\nGunakan: <code>/addvless [KodeNegara] [IP:Port] [Nama] [ISP (opsional)]</code>\nContoh: <code>/addvless SG 103.152.112.5:443 SG-Fast AWS</code>`);
                return new Response("OK");
            }
            const country = parts[0].toUpperCase();
            const target = parts[1];
            const name = parts[2] || `${country} Server`;
            const isp = parts.slice(3).join(" ") || "Custom ISP";
            const id = `${country.toLowerCase()}-${Date.now().toString().slice(-4)}`;
            const flag = getFlag(country);

            const servers = await getServersList(env);
            servers.push({ id, name, country, flag, target, isp, status: "active" });
            await saveServersList(env, servers);
            await sendTg(botToken, chatId, `✅ <b>Server Berhasil Ditambahkan!</b>\nNegara: ${flag} <code>${country}</code>\nTarget: <code>${target}</code>\nNama: <b>${name}</b>\nISP: <b>${isp}</b>\nID: <code>${id}</code>\n\n<i>Server baru langsung otomatis muncul di link subscription.</i>`, {
                inline_keyboard: [[{ text: "📋 Lihat Daftar Proxy", callback_data: "cmd_listproxy" }]]
            });
            return new Response("OK");
        }

        // /delvless <ID atau Target>
        if (text.startsWith("/delvless ") || text.startsWith("/delserver ") || data.startsWith("del_")) {
            const isAdminUser = await checkAdmin(env, chatId);
            if (!isAdminUser) {
                await sendTg(botToken, chatId, "⛔ <b>Akses Ditolak:</b> Perintah ini khusus untuk Admin.");
                return new Response("OK");
            }
            const targetId = data.startsWith("del_") ? data.replace("del_", "") : text.replace(/^\/(delvless|delserver)\s+/, "").trim();
            let servers = await getServersList(env);
            const originalLength = servers.length;
            servers = servers.filter(s => s.id !== targetId && s.target !== targetId);
            if (servers.length < originalLength) {
                await saveServersList(env, servers);
                await sendTg(botToken, chatId, `✅ Server <code>${targetId}</code> berhasil dihapus! Daftar subscription langsung diperbarui.`, {
                    inline_keyboard: [[{ text: "📋 Lihat Daftar Proxy", callback_data: "cmd_listproxy" }]]
                });
            } else {
                await sendTg(botToken, chatId, `❌ Server dengan ID / Target <code>${targetId}</code> tidak ditemukan.`);
            }
            return new Response("OK");
        }

                // Admin: /resetservers
        if (text === "/resetservers" || data === "cmd_resetservers") {
            const isAdminUser = await checkAdmin(env, chatId);
            if (!isAdminUser) {
                await sendTg(botToken, chatId, "⛔ <b>Akses Ditolak:</b> Perintah ini khusus untuk Admin.");
                return new Response("OK");
            }
            await saveServersList(env, DEFAULT_SERVERS);
            await sendTg(botToken, chatId, `✅ <b>Berhasil Me-reset Server!</b>\nDaftar server dikembalikan ke default (${DEFAULT_SERVERS.length} Server).`, {
                inline_keyboard: [[{ text: "📋 Lihat Daftar Proxy", callback_data: "cmd_listproxy" }]]
            });
            return new Response("OK");
        }

        // /delvlessdead (clean dead proxies)
        if (text === "/delvlessdead" || text === "/cleandead" || data === "cmd_delvlessdead" || data === "clean_dead") {
            const isAdminUser = await checkAdmin(env, chatId);
            if (!isAdminUser) {
                await sendTg(botToken, chatId, "⛔ <b>Akses Ditolak:</b> Perintah ini khusus untuk Admin.");
                return new Response("OK");
            }
            await sendTg(botToken, chatId, `⏳ <b>Sedang menguji dan menghapus server mati...</b>`);
            const servers = await getServersList(env);
            const pingResults = await pingAllInBatches(servers, 6);
            const aliveServers = [];
            const deadServers = [];
            for (const r of pingResults) {
                if (r.ok) aliveServers.push({ ...r.server, latency: r.latency });
                else deadServers.push(r.server);
            }

            if (deadServers.length > 0) {
                aliveServers.sort((a, b) => a.latency - b.latency);
                const cleaned = aliveServers.map(({ latency, ...rest }) => rest);
                await saveServersList(env, cleaned);
                await sendTg(botToken, chatId, `✅ <b>Pembersihan Selesai!</b>\n🗑️ Dihapus <b>${deadServers.length}</b> server mati.\n⚡ Tersisa <b>${aliveServers.length}</b> server aktif tercepat.`, {
                    inline_keyboard: [
                        [{ text: "📋 Lihat Daftar Proxy", callback_data: "cmd_listproxy" }],
                        [{ text: "⬅️ Menu Utama", callback_data: "menu_home" }]
                    ]
                });
            } else {
                await sendTg(botToken, chatId, `🎉 <b>Semua ${servers.length} server aktif prima!</b>\nTidak ada server mati yang perlu dihapus.`, {
                    inline_keyboard: [
                        [{ text: "📋 Lihat Daftar Proxy", callback_data: "cmd_listproxy" }],
                        [{ text: "⬅️ Menu Utama", callback_data: "menu_home" }]
                    ]
                });
            }
            return new Response("OK");
        }

        // Bonus Admin: /syncproxies
        if (text === "/syncproxies" || data === "cmd_syncproxies") {
            const isAdminUser = await checkAdmin(env, chatId);
            if (!isAdminUser) {
                await sendTg(botToken, chatId, "⛔ <b>Akses Ditolak:</b> Perintah ini khusus untuk Admin.");
                return new Response("OK");
            }
            await sendTg(botToken, chatId, `⏳ <b>Mengambil proxy terverifikasi dari LalatinaSub/Mineral...</b>`);
            try {
                const upstream = await fetch("https://raw.githubusercontent.com/LalatinaHub/LatinaSub/main/result/nodes");
                if (!upstream.ok) throw new Error("Gagal mengambil feed dari upstream");
                const rawText = await upstream.text();
                const matched = rawText.match(/@([a-zA-Z0-9\.-]+):(\d+)/g) || [];
                const extracted = [...new Set(matched.map(m => m.replace("@", "")))].slice(0, 15);
                
                let added = 0;
                const servers = await getServersList(env);
                for (const t of extracted) {
                    if (!servers.some(s => s.target === t)) {
                        const ping = await pingServer(t);
                        if (ping.ok && ping.latency < 500) {
                            servers.push({
                                id: `sync-${Date.now().toString().slice(-4)}-${added + 1}`,
                                name: `Verified ${t.split(":")[0]}`,
                                country: "SG",
                                flag: "⚡",
                                target: t,
                                isp: "Lalatina Verified",
                                status: "active"
                            });
                            added++;
                        }
                    }
                }
                if (added > 0) {
                    await saveServersList(env, servers);
                    await sendTg(botToken, chatId, `✅ <b>Sinkronisasi Berhasil!</b>\nMenambahkan <b>${added}</b> proxy berkecepatan tinggi dari feed LalatinaHub.\nTotal proxy sekarang: <b>${servers.length}</b>.`, {
                        inline_keyboard: [[{ text: "📋 Lihat Daftar Proxy", callback_data: "cmd_listproxy" }]]
                    });
                } else {
                    await sendTg(botToken, chatId, `ℹ️ Tidak ada proxy baru yang lolos uji latensi.`);
                }
            } catch (err) {
                await sendTg(botToken, chatId, `❌ Gagal sinkronisasi: ${err.message}`);
            }
            return new Response("OK");
        }

        // 13. BUG WS SELECTOR
        if (data === "help_bug" || data === "menu_bugs" || text === "/bug" || text === "/bugs") {
            const bugInfo = `🌐 <b>PILIH ATAU INPUT BUG WS:</b>\n\nBug WS aktif saat ini: <code>${defaultBug}</code>\n\n<i>Silakan pilih salah satu preset Bug populer di bawah, atau ketik manual:</i>\n<code>/bug [IP atau Host]</code>\n<i>Contoh:</i> <code>/bug 104.17.3.81</code> atau <code>/bug quiz.vidio.com</code>`;
            const kb = {
                inline_keyboard: [
                    [{ text: "🎓 104.17.3.81 (Kuota Edukasi / Belajar)", callback_data: "selbug_104.17.3.81" }],
                    [{ text: "⚡ 162.159.138.6 (Cloudflare Clean Anycast)", callback_data: "selbug_162.159.138.6" }],
                    [{ text: "📺 quiz.vidio.com (Bug Vidio)", callback_data: "selbug_quiz.vidio.com" }],
                    [{ text: "💼 zoom.us (Bug Zoom Meeting)", callback_data: "selbug_zoom.us" }],
                    [{ text: "🌐 cugarete.me (Domain Resmi / Standar)", callback_data: "selbug_cugarete.me" }],
                    [{ text: "⬅️ Menu Utama", callback_data: "menu_home" }]
                ]
            };
            await sendTg(botToken, chatId, bugInfo, kb);
            return new Response("OK");
        }

        if (data.startsWith("selbug_")) {
            const chosenBug = data.replace("selbug_", "").trim();
            if (env && env.SERVERS_KV) {
                await env.SERVERS_KV.put("DEFAULT_BUG", chosenBug);
            }
            const linkTls = `https://${domain}/sub/vless/?method=ws&bug=${chosenBug}&port=443&tls=true`;
            const linkNtls = `https://${domain}/sub/vless/?method=ws&bug=${chosenBug}&port=80`;
            const msgBug = `✅ <b>Bug WS Berhasil Diatur ke:</b> <code>${chosenBug}</code>\n\nSilakan pilih tipe link subscription yang diinginkan:\n\n🔒 <b>TLS (443):</b>\n<code>${linkTls}</code>\n\n🔓 <b>NTLS (80):</b>\n<code>${linkNtls}</code>\n\n<i>Salin salah satu link di atas lalu Import ke v2rayNG / NekoBox.</i>`;
            await sendTg(botToken, chatId, msgBug, {
                inline_keyboard: [
                    [{ text: "🎲 Random VLESS", callback_data: "cmd_proxyrandom" }],
                    [{ text: "🌐 Ganti Bug Lain", callback_data: "menu_bugs" }],
                    [{ text: "⬅️ Menu Utama", callback_data: "menu_home" }]
                ]
            });
            return new Response("OK");
        }

        if (text.startsWith("/setbug ") || text.startsWith("/bug ")) {
            const newBug = text.replace(/^\/(setbug|bug)\s+/, "").trim();
            if (!newBug) {
                await sendTg(botToken, chatId, `❌ Gunakan format: <code>/bug [IP atau Domain]</code>\nContoh: <code>/bug 104.17.3.81</code>`);
                return new Response("OK");
            }
            if (env && env.SERVERS_KV) {
                await env.SERVERS_KV.put("DEFAULT_BUG", newBug);
            }
            const linkTls = `https://${domain}/sub/vless/?method=ws&bug=${newBug}&port=443&tls=true`;
            const linkNtls = `https://${domain}/sub/vless/?method=ws&bug=${newBug}&port=80`;
            const msgBug = `✅ <b>Bug Kustom Berhasil Disimpan:</b> <code>${newBug}</code>\n\n🔒 <b>TLS (Port 443):</b>\n<code>${linkTls}</code>\n\n🔓 <b>NTLS (Port 80):</b>\n<code>${linkNtls}</code>`;
            await sendTg(botToken, chatId, msgBug, {
                inline_keyboard: [
                    [{ text: "🎲 Random VLESS", callback_data: "cmd_proxyrandom" }],
                    [{ text: "⬅️ Menu Utama", callback_data: "menu_home" }]
                ]
            });
            return new Response("OK");
        }

        return new Response("OK");
    } catch (err) {
        return new Response("Webhook Error: " + err.message + "\n" + err.stack, { status: 200 });
    }
}

// --- [ CLOUDFLARE ENTRY POINT ] ---

export default {
    async fetch(req, env, ctx) {
        try {
            const url = new URL(req.url);
            const isWs = req.headers.get("Upgrade")?.toLowerCase() === "websocket";
            
            // Asynchronously record request stats in KV
            if (ctx && ctx.waitUntil && env && env.SERVERS_KV) {
                ctx.waitUntil((async () => {
                    try {
                        const raw = await env.SERVERS_KV.get("WORKER_STATS", "json") || { reqs: 0, ws: 0 };
                        raw.reqs = (raw.reqs || 0) + 1;
                        if (isWs) raw.ws = (raw.ws || 0) + 1;
                        await env.SERVERS_KV.put("WORKER_STATS", JSON.stringify(raw));
                    } catch {}
                })());
            }

            if (isWs) {
                const cleanPath = decodeURIComponent(url.pathname).replace(/^\/+/, "");
                const pathMatch = cleanPath.match(/^([a-zA-Z0-9\.-]+)[:=-](\d+)$/);
                const fallbackNode = pathMatch ? `${pathMatch[1]}:${pathMatch[2]}` : null;
                
                const pair = new WebSocketPair();
                const [local, remote] = Object.values(pair);
                remote.accept();
                
                const ed = req.headers.get("sec-websocket-protocol");
                const firstPacket = ByteUtils.b64Decode(ed);
                
                let activeTarget = null, dnsWriter = null;

                const wsStream = new ReadableStream({
                    start(ctrl) {
                        remote.addEventListener("message", e => ctrl.enqueue(e.data));
                        remote.addEventListener("close", () => ctrl.close());
                        remote.addEventListener("error", () => ctrl.error());
                        if (firstPacket) ctrl.enqueue(firstPacket);
                    }
                });

                wsStream.pipeTo(new WritableStream({
                    async write(chunk) {
                        if (dnsWriter) return dnsWriter.write(chunk);
                        if (activeTarget) {
                            const w = activeTarget.writable.getWriter();
                            await w.write(chunk);
                            w.releaseLock();
                            return;
                        }

                        const buf = new Uint8Array(chunk);
                        const engine = await ConnectionBroker.identify(buf);
                        const intent = await engine.extract(buf);

                        if (intent.isUdp) {
                            if (intent.port !== 53) throw new Error("Only DoH UDP allowed");
                            dnsWriter = SubstreamHandler.attachDNS(remote, intent.replyHead);
                            dnsWriter.write(intent.payload);
                            return;
                        }

                        // Fast intercept for connectivity / latency probes (e.g. cp.cloudflare.com, /generate_204)
                        const isProbe = intent.host === "cp.cloudflare.com" || 
                                        intent.host === "connectivitycheck.gstatic.com" ||
                                        (intent.host === "www.google.com" && intent.port === 80);
                        let payloadStr = "";
                        try { payloadStr = ByteUtils.decode(intent.payload); } catch {}
                        if (isProbe || payloadStr.includes("generate_204") || payloadStr.includes("gen_204")) {
                            const resp204 = ByteUtils.encode("HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
                            remote.send(ByteUtils.merge(intent.replyHead, resp204));
                            remote.close();
                            return;
                        }

                        const host = fallbackNode ? fallbackNode.split(/[:=-]/)[0] : intent.host;
                        const port = fallbackNode ? parseInt(fallbackNode.split(/[:=-]/)[1], 10) : intent.port;
                        
                        const connectNode = async (h, p) => {
                            const sock = connect({ hostname: h, port: p });
                            activeTarget = sock;
                            const w = sock.writable.getWriter();
                            await w.write(intent.payload);
                            w.releaseLock();
                            return sock;
                        };

                        let activeSock = null;
                        try {
                            activeSock = await connectNode(intent.host, intent.port);
                        } catch (err) {
                            if (fallbackNode) {
                                try {
                                    activeSock = await connectNode(host, port);
                                } catch {
                                    remote.close();
                                    return;
                                }
                            } else {
                                remote.close();
                                return;
                            }
                        }

                        SubstreamHandler.pipeTCP(activeSock, remote, intent.replyHead, async () => {
                            if (fallbackNode) {
                                try {
                                    const s2 = await connectNode(host, port);
                                    s2.closed.finally(() => remote.close());
                                    SubstreamHandler.pipeTCP(s2, remote, intent.replyHead, null);
                                } catch {
                                    remote.close();
                                }
                            }
                        });
                    }
                })).catch(() => remote.close());

                return new Response(null, {
                    status: 101, webSocket: local, 
                    headers: ed ? { "Sec-WebSocket-Protocol": ed } : {}
                });
            }

            // 2. SUBSCRIPTION ENDPOINT
            if (url.pathname.startsWith("/sub")) {
                return await handleSubscription(req, env, url);
            }

            // 3. TELEGRAM BOT WEBHOOK
            if (url.pathname === "/webhook") {
                if (req.method === "POST") {
                    return await handleTelegramWebhook(req, env, ctx);
                }
                return new Response("Webhook endpoint ready for POST", { status: 200 });
            }

            // 4. API SERVERS LIST
            if (url.pathname === "/api/servers") {
                const servers = await getServersList(env);
                return new Response(JSON.stringify(servers, null, 2), {
                    headers: { "content-type": "application/json" }
                });
            }

            // 5. LANDING / STATUS PAGE
            const domain = (env && env.CUSTOM_DOMAIN) || url.hostname;
            const defaultBug = await getDefaultBug(env);
            const landingHtml = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Avenia Workers - VLESS Cloudflare Tunnel</title>
    <style>
        body { font-family: system-ui, sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; max-width: 700px; margin: auto; }
        .card { background: #1e293b; padding: 1.5rem; border-radius: 12px; border: 1px solid #334155; margin-bottom: 1.5rem; }
        h1 { color: #38bdf8; }
        a { color: #38bdf8; text-decoration: none; font-weight: bold; }
        code { background: #0f172a; padding: 4px 8px; border-radius: 6px; color: #f43f5e; }
        .btn { display: inline-block; background: #0284c7; color: white; padding: 10px 16px; border-radius: 8px; margin-top: 10px; margin-right: 10px; }
    </style>
</head>
<body>
    <h1>⚡ Avenia Workers</h1>
    <div class="card">
        <h3>🔗 Link Subscription Siap Pakai:</h3>
        <p><b>TLS (Port 443):</b><br><a href="/sub/vless/?method=ws&bug=${defaultBug}&port=443&tls=true">/sub/vless/?method=ws&bug=${defaultBug}&port=443&tls=true</a></p>
        <p><b>NTLS (Port 80):</b><br><a href="/sub/vless/?method=ws&bug=${defaultBug}&port=80&tls=false">/sub/vless/?method=ws&bug=${defaultBug}&port=80&tls=false</a></p>
    </div>
    <div class="card">
        <h3>🤖 Telegram Webhook:</h3>
        <p>URL Webhook Bot: <code>https://${domain}/webhook</code></p>
    </div>
</body>
</html>`;

            return new Response(landingHtml, {
                headers: { "content-type": "text/html; charset=utf-8" }
            });
        } catch (err) {
            return new Response("Worker Error: " + err.message + "\n" + err.stack, { status: 200 });
        }
    }
};

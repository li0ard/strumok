import { ALPHA_MUL, ALPHA_MUL_INV, T0, T1, T2, T3, T4, T5, T6, T7 } from "./const";
import { bytesToUint64s, uint64sToBytes } from "./utils";

const byte = (n: number | bigint, w: bigint) => Number((w>>(BigInt(n)*8n)) & 0xffn);
const a_mul = (w: bigint) => (w << 8n) ^ (ALPHA_MUL[Number(w >> 56n)]);
const ainv_mul = (w: bigint) => (w >> 8n) ^ (ALPHA_MUL_INV[Number(w & 0xffn)]);
const T = (w: bigint) => ((T0[byte(0,(w))])^(T1[byte(1,(w))])^(T2[byte(2,(w))])^(T3[byte(3,(w))])^(T4[byte(4,(w))])^(T5[byte(5,(w))])^(T6[byte(6,(w))])^(T7[byte(7,(w))]));
const not = (w: bigint) => {
    const MAX_UINT64 = (1n << 64n) - 1n;
    return MAX_UINT64 - (w & MAX_UINT64);
}

/** Strumok class */
export class Strumok {
    /** Block size */
    public readonly BLOCKSIZE = 128;
    private S: BigUint64Array;
    private r: BigUint64Array;
    private key: BigUint64Array;
    private iv: BigUint64Array;
    private key_size: number;
    
    /**
     * Strumok algorithm
     * @param key Encryption key (32/64 bytes)
     * @param iv Initialization vector (32 bytes)
     */
    constructor(key: Uint8Array, iv: Uint8Array) {
        if(iv.length !== 32) throw new Error("Unsupported IV length");
        this.key = bytesToUint64s(key);
        this.iv = bytesToUint64s(iv);
        this.key_size = key.length;
        this.S = new BigUint64Array(16);
        this.r = new BigUint64Array(2);

        if(this.key_size == 32) {
            this.S[0] = this.key[3] ^ this.iv[0];
            this.S[1] = this.key[2];
            this.S[2] = this.key[1] ^ this.iv[1];
            this.S[3] = this.key[0] ^ this.iv[2];
            this.S[4] = this.key[3];
            this.S[5] = this.key[2] ^ this.iv[3];
            this.S[6] = not(this.key[1]);
            this.S[7] = not(this.key[0]);
            this.S[8] = this.key[3];
            this.S[9] = this.key[2];
            this.S[10] = not(this.key[1]);
            this.S[11] = this.key[0];
            this.S[12] = this.key[3];
            this.S[13] = not(this.key[2]);
            this.S[14] = this.key[1];
            this.S[15] = not(this.key[0]);
        } else if(this.key_size == 64) {
            this.S[0] = this.key[7] ^ this.iv[0];
            this.S[1] = this.key[6];
            this.S[2] = this.key[5];
            this.S[3] = this.key[4] ^ this.iv[1];
            this.S[4] = this.key[3];
            this.S[5] = this.key[2] ^ this.iv[2];
            this.S[6] = this.key[1];
            this.S[7] = not(this.key[0]);
            this.S[8] = this.key[4] ^ this.iv[3];
            this.S[9] = not(this.key[6]);
            this.S[10] = this.key[5];
            this.S[11] = not(this.key[7]);
            this.S[12] = this.key[3];
            this.S[13] = this.key[2];
            this.S[14] = not(this.key[1]);
            this.S[15] = this.key[0];
        } else {
            throw new Error("Unsupported key length");
        }
        this.r[0] = 0n;
        this.r[1] = 0n;

        for (let i = 0; i < 2; i++) {
            let outfrom_fsm: bigint, fsmtmp: bigint;

            outfrom_fsm = (this.r[0] + this.S[15]) ^ this.r[1];
            this.S[0] = a_mul(this.S[0]) ^ this.S[13] ^ ainv_mul(this.S[11]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[13];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[0]) ^ this.r[1];
            this.S[1] = a_mul(this.S[1]) ^ this.S[14] ^ ainv_mul(this.S[12]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[14];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[1]) ^ this.r[1];
            this.S[2] = a_mul(this.S[2]) ^ this.S[15] ^ ainv_mul(this.S[13]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[15];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[2]) ^ this.r[1];
            this.S[3] = a_mul(this.S[3]) ^ this.S[0] ^ ainv_mul(this.S[14]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[0];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[3]) ^ this.r[1];
            this.S[4] = a_mul(this.S[4]) ^ this.S[1] ^ ainv_mul(this.S[15]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[1];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[4]) ^ this.r[1];
            this.S[5] = a_mul(this.S[5]) ^ this.S[2] ^ ainv_mul(this.S[0]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[2];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[5]) ^ this.r[1];
            this.S[6] = a_mul(this.S[6]) ^ this.S[3] ^ ainv_mul(this.S[1]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[3];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[6]) ^ this.r[1];
            this.S[7] = a_mul(this.S[7]) ^ this.S[4] ^ ainv_mul(this.S[2]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[4];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[7]) ^ this.r[1];
            this.S[8] = a_mul(this.S[8]) ^ this.S[5] ^ ainv_mul(this.S[3]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[5];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[8]) ^ this.r[1];
            this.S[9] = a_mul(this.S[9]) ^ this.S[6] ^ ainv_mul(this.S[4]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[6];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[9]) ^ this.r[1];
            this.S[10] = a_mul(this.S[10]) ^ this.S[7] ^ ainv_mul(this.S[5]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[7];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[10]) ^ this.r[1];
            this.S[11] = a_mul(this.S[11]) ^ this.S[8] ^ ainv_mul(this.S[6]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[8];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[11]) ^ this.r[1];
            this.S[12] = a_mul(this.S[12]) ^ this.S[9] ^ ainv_mul(this.S[7]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[9];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[12]) ^ this.r[1];
            this.S[13] = a_mul(this.S[13]) ^ this.S[10] ^ ainv_mul(this.S[8]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[10];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[13]) ^ this.r[1];
            this.S[14] = a_mul(this.S[14]) ^ this.S[11] ^ ainv_mul(this.S[9]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[11];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[14]) ^ this.r[1];
            this.S[15] = a_mul(this.S[15]) ^ this.S[12] ^ ainv_mul(this.S[10]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[12];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;
        }
    }

    /** Generate next keystream */
    next_stream(): BigUint64Array {
        let fsmtmp: bigint;
        let out_stream = new BigUint64Array(16);

        this.S[0] = a_mul(this.S[0]) ^ this.S[13] ^ ainv_mul(this.S[11]);
        fsmtmp = this.r[1] + this.S[13];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[0] = (this.r[0] + this.S[0]) ^ this.r[1] ^ this.S[1];

        this.S[1] = a_mul(this.S[1]) ^ this.S[14] ^ ainv_mul(this.S[12]);
        fsmtmp = this.r[1] + this.S[14];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[1] = (this.r[0] + this.S[1]) ^ this.r[1] ^ this.S[2];

        this.S[2] = a_mul(this.S[2]) ^ this.S[15] ^ ainv_mul(this.S[13]);
        fsmtmp = this.r[1] + this.S[15];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[2] = (this.r[0] + this.S[2]) ^ this.r[1] ^ this.S[3];

        this.S[3] = a_mul(this.S[3]) ^ this.S[0] ^ ainv_mul(this.S[14]);
        fsmtmp = this.r[1] + this.S[0];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[3] = (this.r[0] + this.S[3]) ^ this.r[1] ^ this.S[4];

        this.S[4] = a_mul(this.S[4]) ^ this.S[1] ^ ainv_mul(this.S[15]);
        fsmtmp = this.r[1] + this.S[1];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[4] = (this.r[0] + this.S[4]) ^ this.r[1] ^ this.S[5];

        this.S[5] = a_mul(this.S[5]) ^ this.S[2] ^ ainv_mul(this.S[0]);
        fsmtmp = this.r[1] + this.S[2];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[5] = (this.r[0] + this.S[5]) ^ this.r[1] ^ this.S[6];

        this.S[6] = a_mul(this.S[6]) ^ this.S[3] ^ ainv_mul(this.S[1]);
        fsmtmp = this.r[1] + this.S[3];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[6] = (this.r[0] + this.S[6]) ^ this.r[1] ^ this.S[7];

        this.S[7] = a_mul(this.S[7]) ^ this.S[4] ^ ainv_mul(this.S[2]);
        fsmtmp = this.r[1] + this.S[4];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[7] = (this.r[0] + this.S[7]) ^ this.r[1] ^ this.S[8];

        this.S[8] = a_mul(this.S[8]) ^ this.S[5] ^ ainv_mul(this.S[3]);
        fsmtmp = this.r[1] + this.S[5];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[8] = (this.r[0] + this.S[8]) ^ this.r[1] ^ this.S[9];

        this.S[9] = a_mul(this.S[9]) ^ this.S[6] ^ ainv_mul(this.S[4]);
        fsmtmp = this.r[1] + this.S[6];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[9] = (this.r[0] + this.S[9]) ^ this.r[1] ^ this.S[10];

        this.S[10] = a_mul(this.S[10]) ^ this.S[7] ^ ainv_mul(this.S[5]);
        fsmtmp = this.r[1] + this.S[7];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[10] = (this.r[0] + this.S[10]) ^ this.r[1] ^ this.S[11];

        this.S[11] = a_mul(this.S[11]) ^ this.S[8] ^ ainv_mul(this.S[6]);
        fsmtmp = this.r[1] + this.S[8];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[11] = (this.r[0] + this.S[11]) ^ this.r[1] ^ this.S[12];

        this.S[12] = a_mul(this.S[12]) ^ this.S[9] ^ ainv_mul(this.S[7]);
        fsmtmp = this.r[1] + this.S[9];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[12] = (this.r[0] + this.S[12]) ^ this.r[1] ^ this.S[13];

        this.S[13] = a_mul(this.S[13]) ^ this.S[10] ^ ainv_mul(this.S[8]);
        fsmtmp = this.r[1] + this.S[10];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[13] = (this.r[0] + this.S[13]) ^ this.r[1] ^ this.S[14];

        this.S[14] = a_mul(this.S[14]) ^ this.S[11] ^ ainv_mul(this.S[9]);
        fsmtmp = this.r[1] + this.S[11];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[14] = (this.r[0] + this.S[14]) ^ this.r[1] ^ this.S[15];

        this.S[15] = a_mul(this.S[15]) ^ this.S[12] ^ ainv_mul(this.S[10]);
        fsmtmp = this.r[1] + this.S[12];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[15] = (this.r[0] + this.S[15]) ^ this.r[1] ^ this.S[0];

        return out_stream;
    }

    /** Generate next keystream and perform encryption */
    next_stream_full_crypt(in_: BigUint64Array): BigUint64Array {
        let fsmtmp: bigint;
        let out = new BigUint64Array(16);

        this.S[0] = a_mul(this.S[0]) ^ this.S[13] ^ ainv_mul(this.S[11]);
        fsmtmp = this.r[1] + this.S[13];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[0] = in_[0] ^ (this.r[0] + this.S[0]) ^ this.r[1] ^ this.S[1];

        this.S[1] = a_mul(this.S[1]) ^ this.S[14] ^ ainv_mul(this.S[12]);
        fsmtmp = this.r[1] + this.S[14];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[1] = in_[1] ^ (this.r[0] + this.S[1]) ^ this.r[1] ^ this.S[2];

        this.S[2] = a_mul(this.S[2]) ^ this.S[15] ^ ainv_mul(this.S[13]);
        fsmtmp = this.r[1] + this.S[15];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[2] = in_[2] ^ (this.r[0] + this.S[2]) ^ this.r[1] ^ this.S[3];

        this.S[3] = a_mul(this.S[3]) ^ this.S[0] ^ ainv_mul(this.S[14]);
        fsmtmp = this.r[1] + this.S[0];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[3] = in_[3] ^ (this.r[0] + this.S[3]) ^ this.r[1] ^ this.S[4];

        this.S[4] = a_mul(this.S[4]) ^ this.S[1] ^ ainv_mul(this.S[15]);
        fsmtmp = this.r[1] + this.S[1];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[4] = in_[4] ^ (this.r[0] + this.S[4]) ^ this.r[1] ^ this.S[5];

        this.S[5] = a_mul(this.S[5]) ^ this.S[2] ^ ainv_mul(this.S[0]);
        fsmtmp = this.r[1] + this.S[2];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[5] = in_[5] ^(this.r[0] + this.S[5]) ^ this.r[1] ^ this.S[6];

        this.S[6] = a_mul(this.S[6]) ^ this.S[3] ^ ainv_mul(this.S[1]);
        fsmtmp = this.r[1] + this.S[3];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[6] = in_[6] ^(this.r[0] + this.S[6]) ^ this.r[1] ^ this.S[7];

        this.S[7] = a_mul(this.S[7]) ^ this.S[4] ^ ainv_mul(this.S[2]);
        fsmtmp = this.r[1] + this.S[4];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[7] = in_[7] ^(this.r[0] + this.S[7]) ^ this.r[1] ^ this.S[8];

        this.S[8] = a_mul(this.S[8]) ^ this.S[5] ^ ainv_mul(this.S[3]);
        fsmtmp = this.r[1] + this.S[5];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[8] = in_[8] ^(this.r[0] + this.S[8]) ^ this.r[1] ^ this.S[9];

        this.S[9] = a_mul(this.S[9]) ^ this.S[6] ^ ainv_mul(this.S[4]);
        fsmtmp = this.r[1] + this.S[6];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[9] = in_[9] ^(this.r[0] + this.S[9]) ^ this.r[1] ^ this.S[10];

        this.S[10] = a_mul(this.S[10]) ^ this.S[7] ^ ainv_mul(this.S[5]);
        fsmtmp = this.r[1] + this.S[7];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[10] = in_[10] ^(this.r[0] + this.S[10]) ^ this.r[1] ^ this.S[11];

        this.S[11] = a_mul(this.S[11]) ^ this.S[8] ^ ainv_mul(this.S[6]);
        fsmtmp = this.r[1] + this.S[8];
        this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;
        out[11] = in_[11] ^ (this.r[0] + this.S[11]) ^ this.r[1] ^ this.S[12];

        this.S[12] = a_mul(this.S[12]) ^ this.S[9] ^ ainv_mul(this.S[7]);
        fsmtmp = this.r[1] + this.S[9];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[12] = in_[12] ^ (this.r[0] + this.S[12]) ^ this.r[1] ^ this.S[13];

        this.S[13] = a_mul(this.S[13]) ^ this.S[10] ^ ainv_mul(this.S[8]);
        fsmtmp = this.r[1] + this.S[10];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[13] = in_[13] ^ (this.r[0] + this.S[13]) ^ this.r[1] ^ this.S[14];

        this.S[14] = a_mul(this.S[14]) ^ this.S[11] ^ ainv_mul(this.S[9]);
        fsmtmp = this.r[1] + this.S[11];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[14] = in_[14] ^ (this.r[0] + this.S[14]) ^ this.r[1] ^ this.S[15];

        this.S[15] = a_mul(this.S[15]) ^ this.S[12] ^ ainv_mul(this.S[10]);
        fsmtmp = this.r[1] + this.S[12];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[15] = in_[15] ^ (this.r[0] + this.S[15]) ^ this.r[1] ^ this.S[0];

        return out;
    }

    /** Set new initialization vector */
    setIV(iv: Uint8Array): Strumok { return new Strumok(uint64sToBytes(this.key), iv); }

    /**
     * Perform encryption/decryption
     * @param in_ Input data
     */
    crypt(in_: Uint8Array): Uint8Array {
        const inl = in_.length;
        const out = new Uint8Array(inl);
        let inOffset = 0;
        let outOffset = 0;

        const blockBuffer = new ArrayBuffer(this.BLOCKSIZE);
        const block64 = new BigUint64Array(blockBuffer);
        const block8 = new Uint8Array(blockBuffer);
        while (inl - inOffset >= this.BLOCKSIZE) {
            block8.set(in_.slice(inOffset, inOffset + this.BLOCKSIZE));
        
            const encrypted8 = new Uint8Array(this.next_stream_full_crypt(block64).buffer, 0, this.BLOCKSIZE);
            out.set(encrypted8, outOffset);
        
            inOffset += this.BLOCKSIZE;
            outOffset += this.BLOCKSIZE;
        }

        if (inOffset < inl) {
            const remaining = inl - inOffset;
            const keystream = new Uint8Array(this.next_stream().buffer, 0, this.BLOCKSIZE);
        
            for (let i = 0; i < remaining; i++) out[outOffset + i] = in_[inOffset + i] ^ keystream[i];
        }

        return out;
    }
}
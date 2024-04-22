const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const ripemd160 = require('ripemd160');
const bech32 = require('bech32');


const mempool_dir = 'mempool';


function ripemd160_conversion(data) {
    const hash = new ripemd160().update(data).digest('hex');
    return hash;
}

function hashTxid(txid) {
    const txidBuffer = Buffer.from(txid, 'hex');
    const hashedTxid = crypto.createHash('sha256').update(txidBuffer).digest('hex');
    return hashedTxid;
}

function Locktime_validaion(transaction) {
    const currentTime = Math.floor(Date.now() / 1000);
    const transactionLocktime = transaction.locktime;

    if (transactionLocktime >= 500000000) {
        if (currentTime >= transactionLocktime) {
            return true;
        } else {
            return false;
        }
    } else {
        return true;
    }
}


function Transaction_validation(transaction) {
    const essentialFields = ['vin', 'vout'];

    for (const field of essentialFields) {
        if (!transaction[field] || !Array.isArray(transaction[field]) || transaction[field].length === 0) {
            return false;
        }
    }

    for (const vin of transaction.vin) {
        if (!vin.txid || !vin.vout) {
            return false; 
        }
    }

    for (const vout of transaction.vout) {
        if (!vout.scriptPubKey || Object.keys(vout.scriptPubKey).length === 0) {
            return false; 
        }
    }

    return true;
}

function processMempoolFromFiles() {
    const MEMPOOL_DIR = 'mempool'; 
    const validTransactions = [];

    const files = fs.readdirSync(MEMPOOL_DIR);
    for (const filename of files) {
        const filepath = path.join(MEMPOOL_DIR, filename);
        const data = fs.readFileSync(filepath, 'utf8');
        const transaction = JSON.parse(data);

        if (Locktime_validaion(transaction) || Transaction_validation(transaction)) {
            let valid = 1;
            for (let index = 0; index < transaction.vin.length; index++) {
                const vin = transaction.vin[index];
                try {
                    if (vin.prevout.scriptpubkey_type === 'p2pkh') {
                        if (!verifyP2PKHTransaction(vin, transaction, index)) {
                            valid = 0;
                            break;
                        }
                    } else if (vin.prevout.scriptpubkey_type === 'v0_p2wpkh') {
                        if (!verifyP2WPKHTransaction(vin, transaction, index)) {
                            valid = 0;
                            break;
                        }
                    } else if (vin.prevout.scriptpubkey_type === 'v0_p2wsh') {
                        if (!verifyP2WSHTx(vin, transaction, index)) {
                            valid = 0;
                            break;
                        }
                    } else if (vin.prevout.scriptpubkey_type === 'p2sh') {
                        if (vin.witness) {
                            if (!verifyP2SHP2WPKHTransaction(vin, transaction, index)) {
                                valid = 0;
                                break;
                            }
                        } else {
                            if (!verifyP2SHTransaction(vin, transaction, index)) {
                                valid = 0;
                                break;
                            }
                        }
                    } else {
                        continue;
                    }
                } catch (e) {
                    valid = 0;
                    break;
                }
            }
            if (valid) {
                validTransactions.push(transaction);
            }
        }
    }
    return validTransactions;
}


function areInputsGreaterThanOutputs(transaction) {
    let totalInputValue = 0;
    let totalOutputValue = 0;

    for (const vin of transaction.vin) {
        totalInputValue += vin.prevout.value;
    }

    for (const vout of transaction.vout) {
        totalOutputValue += vout.value;
    }

    return totalInputValue >= totalOutputValue;
}

function serializeVarint(value) {
    if (value < 0xfd) {
        return Buffer.from([value]);
    } else if (value <= 0xffff) {
        const buf = Buffer.allocUnsafe(3);
        buf[0] = 0xfd;
        buf.writeUInt16LE(value, 1);
        return buf;
    } else if (value <= 0xffffffff) {
        const buf = Buffer.allocUnsafe(5);
        buf[0] = 0xfe;
        buf.writeUInt32LE(value, 1);
        return buf;
    } else {
        const buf = Buffer.allocUnsafe(9);
        buf[0] = 0xff;
        buf.writeBigUInt64LE(BigInt(value), 1);
        return buf;
    }
}


function serializeTransaction(tx) {
    const serializedTx = [];

    serializedTx.push(...Buffer.from([tx.version & 0xff, (tx.version >> 8) & 0xff, (tx.version >> 16) & 0xff, (tx.version >> 24) & 0xff]));

    serializedTx.push(...serializeVarint(tx.vin.length));

    for (const vin of tx.vin) {
        serializedTx.push(...Buffer.from(vin.txid, 'hex').reverse());
        serializedTx.push(...Buffer.from([vin.vout & 0xff, (vin.vout >> 8) & 0xff, (vin.vout >> 16) & 0xff, (vin.vout >> 24) & 0xff]));
        const scriptSigLength = vin.scriptsig ? vin.scriptsig.length / 2 : 0;
        serializedTx.push(...serializeVarint(scriptSigLength));
        if (vin.scriptsig) {
            serializedTx.push(...Buffer.from(vin.scriptsig, 'hex'));
        }
        serializedTx.push(...Buffer.from([vin.sequence & 0xff, (vin.sequence >> 8) & 0xff, (vin.sequence >> 16) & 0xff, (vin.sequence >> 24) & 0xff]));
    }

    serializedTx.push(...serializeVarint(tx.vout.length));

    for (const vout of tx.vout) {
        serializedTx.push(...Buffer.from([vout.value & 0xff, (vout.value >> 8) & 0xff, (vout.value >> 16) & 0xff, (vout.value >> 24) & 0xff, (vout.value >> 32) & 0xff, (vout.value >> 40) & 0xff, (vout.value >> 48) & 0xff, (vout.value >> 56) & 0xff]));

        const scriptPubKeyBytes = Buffer.from(vout.scriptpubkey, 'hex');
        serializedTx.push(...serializeVarint(scriptPubKeyBytes.length));
        serializedTx.push(...scriptPubKeyBytes);
    }

    serializedTx.push(...Buffer.from([tx.locktime & 0xff, (tx.locktime >> 8) & 0xff, (tx.locktime >> 16) & 0xff, (tx.locktime >> 24) & 0xff]));

    return Buffer.from(serializedTx);
}


function doubleSha256(s) {
    return crypto.createHash('sha256').update(crypto.createHash('sha256').update(s).digest()).digest();
}

function getTxid(tx) {
    const serializedTx = serializeTransaction(tx);
    const txid = doubleSha256(serializedTx);
    return txid.reverse().toString('hex');
}

function serializeLegacyTx(tx) {
    const serializedTx = [];

    serializedTx.push(...Buffer.from([tx.version & 0xff, (tx.version >> 8) & 0xff, (tx.version >> 16) & 0xff, (tx.version >> 24) & 0xff]));

    serializedTx.push(...serializeVarint(tx.vin.length));

    for (const vin of tx.vin) {
        serializedTx.push(...Buffer.from(vin.txid, 'hex').reverse());
        serializedTx.push(...Buffer.from([vin.vout & 0xff, (vin.vout >> 8) & 0xff, (vin.vout >> 16) & 0xff, (vin.vout >> 24) & 0xff]));
        const scriptSigBytes = Buffer.from(vin.scriptsig, 'hex');
        serializedTx.push(...serializeVarint(scriptSigBytes.length)); 
        serializedTx.push(...scriptSigBytes);
        serializedTx.push(...Buffer.from([vin.sequence & 0xff, (vin.sequence >> 8) & 0xff, (vin.sequence >> 16) & 0xff, (vin.sequence >> 24) & 0xff]));
    }

    serializedTx.push(...serializeVarint(tx.vout.length));

    for (const vout of tx.vout) {
        serializedTx.push(...Buffer.from([vout.value & 0xff, (vout.value >> 8) & 0xff, (vout.value >> 16) & 0xff, (vout.value >> 24) & 0xff, (vout.value >> 32) & 0xff, (vout.value >> 40) & 0xff, (vout.value >> 48) & 0xff, (vout.value >> 56) & 0xff]));

        const scriptPubKeyBytes = Buffer.from(vout.scriptpubkey, 'hex');
        serializedTx.push(...serializeVarint(scriptPubKeyBytes.length)); 
        serializedTx.push(...scriptPubKeyBytes);
    }

    serializedTx.push(...Buffer.from([tx.locktime & 0xff, (tx.locktime >> 8) & 0xff, (tx.locktime >> 16) & 0xff, (tx.locktime >> 24) & 0xff]));

    return Buffer.from(serializedTx);
}


function getLegacyTxid(tx) {
    const serializedTx = serializeLegacyTx(tx);
    const txid = doubleSha256(serializedTx);
    return txid.reverse().toString('hex');
}

function isLegacyTransaction(tx) {
    for (const vin of tx.vin || []) {
        if (vin.witness) {
            return false;
        }
    }
    return true;
}

function HASH160(pubkeyBytes) {
    const sha256Pubkey = crypto.createHash('sha256').update(pubkeyBytes).digest();
    return ripemd160_conversion(sha256Pubkey);
}


function verifyP2WPKHTransaction(vin, transaction, index) {
    const witness = vin.witness;
    const scriptPubKey = vin.prevout.scriptpubkey;
    const providedAddress = vin.prevout.scriptpubkey_address;

    if (witness.length !== 2) {
        return false;
    }

    const [signature, pubkeyHex] = witness;
    const pubkeyBytes = Buffer.from(pubkeyHex, 'hex');

    if (!(pubkeyBytes[0] === 0x02 || pubkeyBytes[0] === 0x03) || pubkeyBytes.length !== 33) {
        return false;
    }

    const ripemd160Pubkey = HASH160(pubkeyBytes);

    const expectedPubkeyHash = Buffer.from(scriptPubKey.slice(4), 'hex');

    if (!ripemd160Pubkey.equals(expectedPubkeyHash)) {
        return false;
    }

    const hrp = "bc";
    const witnessVersion = 0;
    const computedBech32Address = bech32.encode(hrp, witnessVersion, ripemd160Pubkey);
    if (computedBech32Address !== providedAddress) {
        return false;
    }

    let isSignatureValid = false;
    if (signature.slice(-2) === "01") {
        const t = computeSighashP2WPKH(transaction, index, vin.prevout.value);
        isSignatureValid = verifySignature(pubkeyHex, signature.slice(0, -2), t);
    }
    return isSignatureValid;
}


function base58checkDecode(address) {
    const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    let decoded = BigInt(0);
    for (const char of address) {
        decoded = decoded * BigInt(58) + BigInt(alphabet.indexOf(char));
    }
    const decodedBytes = Buffer.from(decoded.toString(16).padStart(50, '0'), 'hex');
    const checksum = decodedBytes.slice(-4);
    const payload = decodedBytes.slice(0, -4);
    if (crypto.createHash('sha256').update(crypto.createHash('sha256').update(payload).digest()).digest().slice(0, 4).equals(checksum)) {
        return payload.slice(1);
    } else {
        throw new Error("Invalid address checksum");
    }
}

function hash256(data) {
    return crypto.createHash('sha256').update(crypto.createHash('sha256').update(data).digest()).digest();
}


function computeSighashP2WPKH(transaction, inputIndex, inputAmount) {
    // 1. Version
    const version = Buffer.alloc(4);
    version.writeUInt32LE(transaction.version, 0);

    // 2. Hashed TXID and VOUT
    const txidVoutPairs = Buffer.concat(transaction.vin.map(vin => Buffer.concat([Buffer.from(vin.txid, 'hex').reverse(), Buffer.alloc(4).writeUInt32LE(vin.vout, 0)])));
    const hashPrevOuts = hash256(txidVoutPairs);

    // 3. Hashed sequences
    const sequences = Buffer.concat(transaction.vin.map(vin => Buffer.alloc(4).writeUInt32LE(vin.sequence, 0)));
    const hashSequence = hash256(sequences);

    // 4. Outpoint
    const outpoint = Buffer.concat([Buffer.from(transaction.vin[inputIndex].txid, 'hex').reverse(), Buffer.alloc(4).writeUInt32LE(transaction.vin[inputIndex].vout, 0)]);

    // 5. ScriptCode
    const pubkeyHash = Buffer.from(transaction.vin[inputIndex].prevout.scriptpubkey.substring(4), 'hex');
    const scriptCode = Buffer.from('1976a914' + pubkeyHash.toString('hex') + '88ac', 'hex');

    // 6. Input amount
    const value = Buffer.alloc(8);
    value.writeBigUInt64LE(BigInt(inputAmount), 0);

    // 7. Sequence
    const sequence = Buffer.alloc(4);
    sequence.writeUInt32LE(transaction.vin[inputIndex].sequence, 0);

    // 8. Hashed outputs
    const serializedOutputs = Buffer.concat(transaction.vout.map(vout => Buffer.concat([Buffer.alloc(8).writeBigUInt64LE(BigInt(vout.value), 0), serializeVarint(Buffer.from(vout.scriptpubkey, 'hex').length), Buffer.from(vout.scriptpubkey, 'hex')])));
    const hashOutputs = hash256(serializedOutputs);

    // 9. Locktime
    const locktime = Buffer.alloc(4);
    locktime.writeUInt32LE(transaction.locktime, 0);

    // 10. SIGHASH type
    const sighashType = transaction.vin[inputIndex].witness[0].slice(-2) === "01" ? Buffer.alloc(4, 1, 'little') : Buffer.alloc(4);
    sighashType.writeUInt32LE(0x81, 0); // SIGHASH_ANYONECANPAY | SIGHASH_ALL

    // 11. Combine for preimage
    const preimage = Buffer.concat([version, hashPrevOuts, hashSequence, outpoint, scriptCode, value, sequence, hashOutputs, locktime, sighashType]);

    // 12. Hash the preimage
    return hash256(preimage).toString('hex');
}

function verifyP2PKHTransaction(vin, transaction, index) {
    const scriptSigHex = vin.scriptsig;
    const scriptPubKey = vin.prevout.scriptpubkey;
    const providedAddress = vin.prevout.scriptpubkey_address;

    const sigEnd = parseInt(scriptSigHex.slice(0, 2), 16) * 2 + 2;
    const signatureHex = scriptSigHex.slice(2, sigEnd);
    const pubkeyHex = scriptSigHex.slice(sigEnd + 2);

    const pubkeyBytes = Buffer.from(pubkeyHex, 'hex');

    const ripemd160Pubkey = HASH160(pubkeyBytes);

    const expectedPubkeyHash = scriptPubKey.slice(6, 46); 


    if (!ripemd160Pubkey.equals(Buffer.from(expectedPubkeyHash, 'hex'))) {
        return false;
    }

    const decodedPubkeyHash = base58checkDecode(providedAddress);

    if (!ripemd160Pubkey.equals(decodedPubkeyHash)) {
        return false;
    }

    let isSignatureValid = true;
    const sighashType = signatureHex.slice(-2);
    let t;
    if (sighashType === '01') {
        t = computeSighashAll(transaction, index);
    } else if (sighashType === '81') {
        t = computeSighashAnyoneCanPayAll(transaction, index);
    }
    isSignatureValid = verifySignature(pubkeyHex, signatureHex.slice(0, -2), t);
    return isSignatureValid;
}


function computeSighashAll(transaction, inputIndex) {
    let serializedTx = Buffer.alloc(0);

    serializedTx = Buffer.concat([serializedTx, Buffer.alloc(4)]);
    serializedTx.writeUInt32LE(transaction.version, 0);

    serializedTx = Buffer.concat([serializedTx, serializeVarint(transaction.vin.length)]);

    for (let i = 0; i < transaction.vin.length; i++) {
        const vin = transaction.vin[i];
        const txid = Buffer.from(vin.txid, 'hex').reverse();
        const vout = Buffer.alloc(4);
        vout.writeUInt32LE(vin.vout, 0);
        let script = Buffer.alloc(0);
        if (i === inputIndex) {
            script = Buffer.from(vin.prevout.scriptpubkey, 'hex');
        }
        const scriptLen = serializeVarint(script.length);
        const sequence = Buffer.alloc(4);
        sequence.writeUInt32LE(vin.sequence, 0);
        serializedTx = Buffer.concat([serializedTx, txid, vout, scriptLen, script, sequence]);
    }

    serializedTx = Buffer.concat([serializedTx, serializeVarint(transaction.vout.length)]);

    for (const vout of transaction.vout) {
        const value = Buffer.alloc(8);
        value.writeBigUInt64LE(BigInt(vout.value), 0);
        const scriptPubkey = Buffer.from(vout.scriptpubkey, 'hex');
        const scriptPubkeyLen = serializeVarint(scriptPubkey.length);
        serializedTx = Buffer.concat([serializedTx, value, scriptPubkeyLen, scriptPubkey]);
    }

    serializedTx = Buffer.concat([serializedTx, Buffer.alloc(4)]);
    serializedTx.writeUInt32LE(transaction.locktime, 0);

    serializedTx = Buffer.concat([serializedTx, Buffer.alloc(4)]);
    serializedTx.writeUInt32LE(1, 0);

    const sighash = crypto.createHash('sha256').update(serializedTx).digest();
    return sighash.toString('hex');
}

function computeSighashAnyoneCanPayAll(transaction, inputIndex) {
    let serializedTx = Buffer.alloc(0);

    serializedTx = Buffer.concat([serializedTx, Buffer.alloc(4)]);
    serializedTx.writeUInt32LE(transaction.version, 0);

    serializedTx = Buffer.concat([serializedTx, serializeVarint(1)]);

    const vin = transaction.vin[inputIndex];
    const txid = Buffer.from(vin.txid, 'hex').reverse();
    const vout = Buffer.alloc(4);
    vout.writeUInt32LE(vin.vout, 0);
    const script = Buffer.from(vin.prevout.scriptpubkey, 'hex'); 
    const sequence = Buffer.alloc(4);
    sequence.writeUInt32LE(vin.sequence, 0);
    const scriptLen = serializeVarint(script.length);
    serializedTx = Buffer.concat([serializedTx, txid, vout, scriptLen, script, sequence]);

    serializedTx = Buffer.concat([serializedTx, serializeVarint(transaction.vout.length)]);
    for (const vout of transaction.vout) {
        const value = Buffer.alloc(8);
        value.writeBigUInt64LE(BigInt(vout.value), 0);
        const scriptPubkey = Buffer.from(vout.scriptpubkey, 'hex');
        const scriptPubkeyLen = serializeVarint(scriptPubkey.length);
        serializedTx = Buffer.concat([serializedTx, value, scriptPubkeyLen, scriptPubkey]);
    }

    serializedTx = Buffer.concat([serializedTx, Buffer.alloc(4)]);
    serializedTx.writeUInt32LE(transaction.locktime, 0);
    serializedTx = Buffer.concat([serializedTx, Buffer.alloc(4)]);
    serializedTx.writeUInt32LE(0x81, 0);

    const sighash = crypto.createHash('sha256').update(serializedTx).digest();
    return sighash.toString('hex');
}


function verifySignature(pubkeyHex, signatureDerHex, messageHex) {
    const pubkeyBytes = Buffer.from(pubkeyHex, 'hex');
    const signatureDerBytes = Buffer.from(signatureDerHex, 'hex');
    const messageHashBytes = Buffer.from(messageHex, 'hex');

    const vk = new ECKey(pubkeyBytes, 'hex');

    const parsedSignature = jrs.fromDER(signatureDerBytes);
    const r = parsedSignature.r;
    const s = parsedSignature.s;

    const signatureBytes = Buffer.concat([Buffer.from(r.toString(16), 'hex'), Buffer.from(s.toString(16), 'hex')]);

    try {
        const is_valid = vk.verify(messageHashBytes, signatureBytes);
        return is_valid;
    } catch (e) {
        return false;
    }
}


function verifyP2SHP2WPKHTransaction(vin, transaction, index) {
    const scriptSig = vin.scriptsig;
    const scriptPubKey = vin.prevout.scriptpubkey;
    const witness = vin.witness;
    const providedAddress = vin.prevout.scriptpubkey_address;

    const redeemScriptHex = vin.scriptsig_asm.split(" ").pop();
    const redeemScript = Buffer.from(redeemScriptHex, 'hex');

    if (redeemScript.length > 520) {
        return false;
    }

    const redeemScriptHash = HASH160(redeemScript);
    const expectedScriptHash = scriptPubKey.slice(4, 44);
    if (redeemScriptHash.toString('hex') !== expectedScriptHash.toString('hex')) {
        return false;
    }

    const decodedPubkeyHash = base58checkDecode(providedAddress);

    if (redeemScriptHash.toString('hex') !== decodedPubkeyHash.toString('hex')) {
        return false;
    }

    let isSignatureValid = true;
    if (witness.length === 2) {
        const [signatureHex, pubkeyHex] = witness;
        const t = computeSighashP2shP2wpkh(transaction, index, vin.prevout.value);
        isSignatureValid = verifySignature(pubkeyHex, signatureHex.slice(0, -2), t);

        return isSignatureValid;
    } else {
        const sig = witness.filter(w => w !== "");
        const innerWitnessScript = vin.inner_witnessscript_asm.split(" ");
        const pub = [];
        for (let i = 0; i < innerWitnessScript.length; i++) {
            if (innerWitnessScript[i] === "OP_PUSHBYTES_33") {
                pub.push(innerWitnessScript[i + 1]);
            }
        }
        const t = computeSighashP2shP2wpkhMulti(transaction, index, vin.prevout.value);
        let j = 0;
        for (const i of pub) {
            if (verifySignature(i, sig[j].slice(0, -2), t)) {
                j++;
            }
            if (j === sig.length) break;
        }

        if (j === sig.length) return true;
        return false;
    }
}


function computeSighashP2shP2wpkhMulti(transaction, input_index, input_amount) {
    // 1. Version
    const version = transaction.version.toBuffer(4);

    // 2. Hashed TXID and VOUT
    const txidVoutPairs = Buffer.concat(transaction.vin.map(vin => Buffer.concat([Buffer.from(vin.txid, 'hex').reverse(), Buffer.alloc(4).writeUInt32LE(vin.vout)])));
    const hashPrevOuts = hash256(txidVoutPairs);

    // 3. Hashed sequences
    const sequences = Buffer.concat(transaction.vin.map(vin => vin.sequence.toBuffer(4)));
    const hashSequence = hash256(sequences);

    // 4. Outpoint
    const outpoint = Buffer.concat([Buffer.from(transaction.vin[input_index].txid, 'hex').reverse(), Buffer.alloc(4).writeUInt32LE(transaction.vin[input_index].vout)]);

    // 5. ScriptCode
    const witnessScript = Buffer.from(transaction.vin[input_index].witness[transaction.vin[input_index].witness.length - 1], 'hex');
    const scriptcode = Buffer.concat([serializeVarint(witnessScript.length), witnessScript]);

    // 6. Input amount
    const value = Buffer.alloc(8);
    value.writeBigUInt64LE(BigInt(input_amount));

    // 7. Sequence
    const sequence = transaction.vin[input_index].sequence.toBuffer(4);

    // 8. Hashed outputs
    const serializedOutputs = Buffer.concat(transaction.vout.map(vout => {
        const valueBuffer = Buffer.alloc(8);
        valueBuffer.writeBigUInt64LE(BigInt(vout.value));
        const scriptpubkeyBuffer = Buffer.from(vout.scriptpubkey, 'hex');
        return Buffer.concat([valueBuffer, serializeVarint(scriptpubkeyBuffer.length), scriptpubkeyBuffer]);
    }));
    const hashOutputs = hash256(serializedOutputs);

    // 9. Locktime
    const locktime = transaction.locktime.toBuffer(4);

    // 10. SIGHASH type
    const sighashtype = Buffer.alloc(4);
    sighashtype.writeUInt32LE(1);

    // 11. Combine for preimage
    const preimage = Buffer.concat([version, hashPrevOuts, hashSequence, outpoint, scriptcode, value, sequence, hashOutputs, locktime, sighashtype]);
    // 12. Hash the preimage
    const sighash = hash256(preimage);
    return sighash.toString('hex');
}



function computeSighashP2shP2wpkh(transaction, input_index, input_amount) {
    // 1. Version
    const version = transaction.version.toBuffer(4);

    // 2. Hashed TXID and VOUT
    const txidVoutPairs = Buffer.concat(transaction.vin.map(vin => Buffer.concat([Buffer.from(vin.txid, 'hex').reverse(), Buffer.alloc(4).writeUInt32LE(vin.vout)])));
    const hashPrevOuts = hash256(txidVoutPairs);

    // 3. Hashed sequences
    const sequences = Buffer.concat(transaction.vin.map(vin => vin.sequence.toBuffer(4)));
    const hashSequence = hash256(sequences);

    // 4. Outpoint
    const outpoint = Buffer.concat([Buffer.from(transaction.vin[input_index].txid, 'hex').reverse(), Buffer.alloc(4).writeUInt32LE(transaction.vin[input_index].vout)]);

    // 5. ScriptCode
    const pubkeyHash = transaction.vin[input_index].inner_redeemscript_asm.split(' ').slice(-1)[0];
    const scriptcode = Buffer.from(`1976a914${pubkeyHash}88ac`, 'hex');

    // 6. Input amount
    const value = Buffer.alloc(8);
    value.writeBigUInt64LE(BigInt(input_amount));

    // 7. Sequence
    const sequence = transaction.vin[input_index].sequence.toBuffer(4);

    // 8. Hashed outputs
    const serializedOutputs = Buffer.concat(transaction.vout.map(vout => {
        const valueBuffer = Buffer.alloc(8);
        valueBuffer.writeBigUInt64LE(BigInt(vout.value));
        const scriptpubkeyBuffer = Buffer.from(vout.scriptpubkey, 'hex');
        return Buffer.concat([valueBuffer, serializeVarint(scriptpubkeyBuffer.length), scriptpubkeyBuffer]);
    }));
    const hashOutputs = hash256(serializedOutputs);

    // 9. Locktime
    const locktime = transaction.locktime.toBuffer(4);

    // 10. SIGHASH type
    let sighashtype;
    if (transaction.vin[input_index].witness[0].slice(-2) === '01') {
        sighashtype = Buffer.alloc(4);
        sighashtype.writeUInt32LE(1);
    } else {
        sighashtype = Buffer.alloc(4);
        sighashtype.writeUInt32LE(0x83); // SIGHASH_ANYONECANPAY | SIGHASH_ALL
    }

    // 11. Combine for preimage
    const preimage = Buffer.concat([version, hashPrevOuts, hashSequence, outpoint, scriptcode, value, sequence, hashOutputs, locktime, sighashtype]);
    // 12. Hash the preimage
    const sighash = hash256(preimage);
    return sighash.toString('hex');
}



function verifyP2SHTransaction(vin, transaction, index) {
    const scriptSig = vin.scriptsig;
    const scriptPubKey = vin.prevout.scriptpubkey;
    const providedAddress = vin.prevout.scriptpubkey_address;

    // Extract the redeem script from scriptSig for P2SH(P2WPKH)
    const redeemScriptHex = vin.scriptsig_asm.split(' ').slice(-1)[0]; // Skipping the push byte for simplicity
    const redeemScript = Buffer.from(redeemScriptHex, 'hex');

    if (redeemScript.length > 520) {
        return false;
    }

    // Validate redeem script hash against scriptPubKey
    const redeemScriptHash = HASH160(redeemScript);
    const expectedScriptHash = scriptPubKey.slice(4, 44); // Extract from OP_HASH160 <hash> OP_EQUAL
    if (redeemScriptHash.toString('hex') !== expectedScriptHash) {
        return false;
    }

    const decodedPubkeyHash = base58checkDecode(providedAddress);

    if (redeemScriptHash.toString('hex') !== decodedPubkeyHash.toString('hex')) {
        return false;
    }

    const t = computeSighashP2sh(transaction, index);
    const sig = [];
    const componentsSig = vin.scriptsig_asm.split(' ').slice(2, -2);
    for (let i = 0; i < componentsSig.length; i += 2) {
        sig.push(componentsSig[i]);
    }

    const pubkey = [];
    const componentsPubkey = vin.inner_redeemscript_asm.split(' ').slice(2, -2);
    for (let i = 0; i < componentsPubkey.length; i += 2) {
        pubkey.push(componentsPubkey[i]);
    }

    let j = 0;
    for (const i of pubkey) {
        if (verifySignature(i, sig[j].slice(0, -2), t)) {
            j += 1;
        }
        if (j === sig.length) {
            break;
        }
    }

    return j === sig.length;
}


function computeSighashP2sh(transaction, inputIndex = -1) {
    let serialized = transaction.version.toString(16).padStart(8, '0');

    serialized += transaction.vin.length.toString(16).padStart(2, '0');

    for (let index = 0; index < transaction.vin.length; index++) {
        const inputItem = transaction.vin[index];
        const txid = Buffer.from(inputItem.txid, 'hex').reverse().toString('hex');
        serialized += txid;

        const vout = inputItem.vout.toString(16).padStart(8, '0');
        serialized += vout;

        if (index === inputIndex || inputIndex === -1) {
            const scriptsigAsm = inputItem.scriptsig_asm ? inputItem.scriptsig_asm.split(' ') : [];
            const redeemScript = scriptsigAsm[scriptsigAsm.length - 1] || '';
            const redeemScriptBytes = Buffer.from(redeemScript, 'hex');
            const scriptLength = redeemScriptBytes.length.toString(16).padStart(2, '0');
            serialized += scriptLength + redeemScript;
        } else {
            serialized += '00'; 
        }

        const sequence = inputItem.sequence.toString(16).padStart(8, '0');
        serialized += sequence;
    }

    serialized += transaction.vout.length.toString(16).padStart(2, '0');

    for (const output of transaction.vout) {
        const value = output.value.toString(16).padStart(16, '0');
        serialized += value;

        const scriptpubkey = Buffer.from(output.scriptpubkey, 'hex').toString('hex');
        const scriptLength = scriptpubkey.length.toString(16).padStart(2, '0');
        serialized += scriptLength + scriptpubkey;
    }

    const locktime = transaction.locktime.toString(16).padStart(8, '0');
    serialized += locktime;

    serialized += '01000000';
    const sighash = hash256(Buffer.from(serialized, 'hex')).toString('hex');
    return sighash;
}

function verifyP2WSHTx(vin, transaction, index) {
    const providedScriptPubKey = vin.prevout.scriptpubkey;
    const providedAddress = vin.prevout.scriptpubkey_address;

    const expectedSha256Hash = providedScriptPubKey.slice(4);

    const witnessScriptAsm = vin.witness;
    const witnessScriptBytes = Buffer.from(witnessScriptAsm[witnessScriptAsm.length - 1], 'hex');
    const calculatedSha256Hash = crypto.createHash('sha256').update(witnessScriptBytes).digest('hex');

    if (calculatedSha256Hash !== expectedSha256Hash) {
        return false;
    }

    const scriptHashHex = expectedSha256Hash;
    const scriptHashBytes = Buffer.from(scriptHashHex, 'hex');

    const hrp = "bc"; 
    const witnessVersion = 0;
    const computedBech32Address = bech32.encode(hrp, witnessVersion, scriptHashBytes);

    if (computedBech32Address !== providedAddress) {
        return false;
    }

    const witness = vin.witness;
    const sig = [];
    for (const item of witness) {
        if (item !== "") {
            sig.push(item);
        }
    }

    const innerWitnessScript = vin.inner_witnessscript_asm.split(" ");
    const pub = [];
    for (let i = 0; i < innerWitnessScript.length; i++) {
        if (innerWitnessScript[i] === "OP_PUSHBYTES_33") {
            pub.push(innerWitnessScript[i + 1]);
        }
    }
    const t = computeSighashP2shP2wpkhMulti(transaction, index, vin.prevout.value);
    let j = 0;
    for (const item of pub) {
        if (verifySignature(item, sig[j].slice(0, -2), t)) {
            j++;
        }
        if (j === sig.length) {
            break;
        }
    }

    return j === sig.length;
}


function calculateTransactionWeight(tx) {
    let nonWitnessBytes = 0;
    let witnessBytes = 0;

    const txType = tx.vin.some(vin => 'witness' in vin) ? 'SEGWIT' : 'LEGACY';

    if (txType === 'LEGACY') {
        nonWitnessBytes += 4; // VERSION

        if (tx.vin.length >= 50) {
            throw new Error("Too many inputs");
        }

        nonWitnessBytes += 1; // INPUT COUNT

        for (const input of tx.vin) {
            nonWitnessBytes += 32; // TXID
            nonWitnessBytes += 4; // VOUT
            const scriptSig = Buffer.from(input.scriptsig || '', 'hex');
            nonWitnessBytes += 1 + scriptSig.length; // SCRIPTSIG
            nonWitnessBytes += 4; // SEQUENCE
        }

        if (tx.vout.length >= 50) {
            throw new Error("Too many outputs");
        }

        nonWitnessBytes += 1; // OUTPUT COUNT

        for (const output of tx.vout) {
            nonWitnessBytes += 8; // VALUE
            const scriptPubKey = Buffer.from(output.scriptpubkey, 'hex');
            nonWitnessBytes += 1 + scriptPubKey.length; // SCRIPTPUBKEY
        }

        nonWitnessBytes += 4; // LOCKTIME
    } else {
        nonWitnessBytes += 4; // VERSION
        witnessBytes += 2; // MARKER and FLAG (witness data)

        if (tx.vin.length >= 100) {
            throw new Error("Too many inputs");
        }

        nonWitnessBytes += 1; // INPUT COUNT

        for (const input of tx.vin) {
            nonWitnessBytes += 32 + 4; // TXID and VOUT
            const scriptSig = Buffer.from(input.scriptsig || '', 'hex');
            nonWitnessBytes += 1 + scriptSig.length; // SCRIPTSIG
            nonWitnessBytes += 4; // SEQUENCE
        }

        if (tx.vout.length >= 255) {
            throw new Error("Too many outputs");
        }

        nonWitnessBytes += 1; // OUTPUT COUNT

        for (const output of tx.vout) {
            nonWitnessBytes += 8; // VALUE
            const scriptPubKey = Buffer.from(output.scriptpubkey, 'hex');
            nonWitnessBytes += 1 + scriptPubKey.length; // SCRIPTPUBKEY
        }

        for (const input of tx.vin) {
            const witness = input.witness || [];
            for (const item of witness) {
                const itemBytes = Buffer.from(item, 'hex');
                witnessBytes += 1 + itemBytes.length;
            }
        }

        nonWitnessBytes += 4; // LOCKTIME
    }

    // Calculate the total weight of the transaction
    const txWeight = nonWitnessBytes * 4 + witnessBytes;

    // Return the transaction weight
    return txWeight;
}



function calculateFees(transaction) {
    let totalInputValue = 0;
    let totalOutputValue = 0;

    for (const vin of transaction.vin) {
        totalInputValue += vin.prevout.value;
    }

    for (const vout of transaction.vout) {
        totalOutputValue += vout.value;
    }

    return totalInputValue - totalOutputValue;
}


function bestTransactionsForBlock(validTransactions) {
    const selectedTransactions = [];
    let totalBlockWeight = 0;
    const maxBlockWeight = 4000000;
    let totalFees = 0;

    const transactionsWithFees = validTransactions.map(transaction => {
        const fees = calculateFees(transaction);
        totalFees += fees;
        return {...transaction, fees};
    });

    const sortedTransactions = transactionsWithFees.sort((a, b) => b.fees - a.fees);

    for (const transaction of sortedTransactions) {
        if (totalBlockWeight + calculateTransactionWeight(transaction) <= maxBlockWeight) {
            selectedTransactions.push(transaction);
            totalBlockWeight += calculateTransactionWeight(transaction);
        } else {
            break;
        }
    }

    return { selectedTransactions, totalFees };
}

function returnId(transactions) {
    const id = [];
    const wid = [];

    transactions.forEach(tx => {
        if (isLegacyTransaction(tx)) {
            id.push(getLegacyTxid(tx));
        } else {
            id.push(getTxid(tx));
            wid.push(getTxid(tx));
        }
    });

    return { id, wid };
}

function reverseByteOrder(txids) {
    return txids.map(txid => txid.match(/.{2}/g).reverse().join(''));
}



function merkleRoot(txids) {
    txids = reverseByteOrder(txids);
    let hashes = txids.map(txid => Buffer.from(txid, 'hex'));

    while (hashes.length > 1) {
        if (hashes.length % 2 === 1) {
            hashes.push(hashes[hashes.length - 1]);
        }
        
        const newHashes = [];
        for (let i = 0; i < hashes.length; i += 2) {
            const combinedHash = Buffer.concat([hashes[i], hashes[i + 1]]);
            const hash = crypto.createHash('sha256').update(combinedHash).digest();
            newHashes.push(hash);
        }
        hashes = newHashes;
    }

    return hashes[0].toString('hex');
}

function witnessCommitment(txs) {       
    const root = merkleRoot(txs);
    const reserved = '00'.repeat(32); // 32 bytes of zero
    const combined = root + reserved;
    const doubleHash = doubleSha256(Buffer.from(combined, 'hex'));
    return doubleHash.toString('hex');
}


function coinbase(txs) {
    const tx = Buffer.alloc(101); 
    tx.writeUInt32LE(1, 0); 
    tx.writeUInt8(0x00, 4); 
    tx.writeUInt8(0x01, 5);
    tx.writeUInt8(0x01, 6);
    tx.fill(0x00, 7, 39); 
    tx.writeUInt32LE(0xFFFFFFFF, 39);
    tx.writeUInt8(0x00, 43); 
    tx.writeUInt32LE(0xFFFFFFFF, 44); 
    tx.writeUInt8(0x02, 48);

    tx.writeBigUInt64LE(BigInt(5000000000), 49); 
    tx.writeUInt8(0x19, 57);
    Buffer.from('76a914edf10a7fac6b32e24daa5305c723f3ee58db1bc888ac', 'hex').copy(tx, 58); 

    tx.fill(0x00, 59, 67);
    const script1 = Buffer.from('6a24aa21a9ed', 'hex');
    const script2 = Buffer.from(witnessCommitment(txs), 'hex');
    const script = Buffer.concat([script1, script2]);
    tx.writeUInt8(script.length, 67);
    script.copy(tx, 68); 

    const scriptLength = 68 + script.length;
    if (scriptLength <= tx.length) {
        tx.writeUInt8(0x21, scriptLength);
    } else {
        console.error('Error: Buffer overflow');
    }
    const endIndex = 101 + script.length;
    if (endIndex <= tx.length) {
        tx.fill(0x00, 69 + script.length, endIndex);
    } else {
        console.error('Error: Buffer overflow');
    }

    const offset = 101 + script.length;
    if (offset + 4 <= tx.length) {
        tx.writeUInt32LE(0x00000000, offset);
    } else {
        console.error('Error: Offset is out of range');
    }

    const txid = doubleSha256(tx);
    return [tx.toString('hex'), txid.reverse().toString('hex')];
}


function createBlockHeader(merkleRoot) {
    const version = 0x20000000; 
    const prevBlockHash = '64' + '00'.repeat(31); 
    const prevBlockHashBytes = Buffer.from(prevBlockHash, 'hex'); 

    const difficultyTarget = '0000ffff00000000000000000000000000000000000000000000000000000000';
    const bits = "1f00ffff";
    const bitsBytes = Buffer.alloc(4);
    bitsBytes.writeUInt32LE(bits, 0);

    const merkleRootBytes = Buffer.from(merkleRoot, 'hex').reverse();
    const timestamp = Math.floor(Date.now() / 1000);
    const timestampBytes = Buffer.alloc(4);
    timestampBytes.writeUInt32LE(timestamp, 0);

    let nonce = 0;
    const target = BigInt('0x' + difficultyTarget);
    const targetBytes = Buffer.alloc(32);
    
    const MAX_INT64 = BigInt(2) ** BigInt(63) - BigInt(1);
    const MIN_INT64 = -MAX_INT64 - BigInt(1);

    if (target >= MIN_INT64 && target <= MAX_INT64) {
        targetBytes.writeBigInt64BE(target, 0);
    } else {
        console.error('Error: Target value is out of range');
    }

    let header;
    while (true) {
        const nonceBytes = Buffer.alloc(4);
        nonceBytes.writeUInt32LE(nonce, 0);
        header = Buffer.concat([
            Buffer.alloc(4),
            prevBlockHashBytes,
            merkleRootBytes,
            timestampBytes,
            bitsBytes,
            nonceBytes
        ]);
        header.writeUInt32LE(version, 0);
        const blockHash = crypto.createHash('sha256').update(crypto.createHash('sha256').update(header).digest()).digest();

        if (BigInt('0x' + blockHash.reverse().toString('hex')) < target) {
            break;
        }
        nonce++;
    }

    return header.toString('hex');
}

const BLOCK_HEIGHT = 840000;
const SUBSIDY = 3.125 * 100000000;

const transactions = processMempoolFromFiles();

const best_tranaction_from_block = bestTransactionsForBlock(transactions);
const bestTransactions = best_tranaction_from_block.selectedTransactions;
const amount = best_tranaction_from_block.totalFees;

let totalAmount = BigInt(amount) + BigInt(SUBSIDY);
totalAmount = totalAmount.toString(16).padStart(16, '0'); 

const returned_id = returnId(bestTransactions);
const txIds = returned_id.id;
const wid = returned_id.wid;

const [coinbaseTxn, coinbaseId] = coinbase(wid);
txIds.unshift(coinbaseId);


const root = merkleRoot(txIds);

const blockHeader = createBlockHeader(root);

const outputContent = `${blockHeader}\n${coinbaseTxn}\n${txIds.join('\n')}`;

const outputFilePath = 'output.txt';
fs.writeFileSync(outputFilePath, outputContent);

console.log('Block generated successfully!');
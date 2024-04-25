const fs = require('fs');
const crypto = require('crypto');


var considerationArray = [];
var weightArray = [];
var txidArray = [];
var txidReverse = [];
var fileNameAfterOperation = [];
var fileArray = [];
var txids = [];

function reversedBytes(bytes) {
    const reversedBytesArray = Buffer.alloc(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
        reversedBytesArray[i] = bytes[bytes.length - 1 - i];
    }
    return [...reversedBytesArray];
}


function uint16ToBytes(n) {
    const buffer = Buffer.allocUnsafe(2); 
    buffer.writeUInt16LE(Number(n) & 0xffff, 0);
    return [...buffer];
}


function uint32ToBytes(n) {
    const buffer = Buffer.allocUnsafe(4);
    buffer.writeUInt32LE(Number(n) & 0xffffffff, 0);
    return [...buffer];
}


function uint64ToBytes(n) {
    const lower = n >>> 0; 
    const upper = (n - lower) / 2 ** 32 >>> 0; 
    const buffer = Buffer.allocUnsafe(8); 
    buffer.writeUInt32LE(lower, 0); 
    buffer.writeUInt32LE(upper, 4);
    return [...buffer];
}

function singleSHA256(data) {
    return crypto.createHash('sha256').update(Buffer.from(data, 'hex')).digest('hex');
}

function doubleSHA256(data) {
    const hash1 = crypto.createHash('sha256').update(Buffer.from(data, 'hex')).digest();
    const hash2 = crypto.createHash('sha256').update(hash1).digest('hex');
    return hash2;
}

function reverseHex(hexString) {
    const reversedHexString = [];
    for (let i = hexString.length - 2; i >= 0; i -= 2) {
        reversedHexString.push(hexString.substr(i, 2));
    }
    return reversedHexString.join('');
}


function serializeVarInt(n) {
    if (n < 0xfd) {
        return [n]; 
    } else if (n <= 0xffff) {
        return [0xfd, ...uint16ToBytes(n)];
    } else if (n <= 0xffffffff) {
        return [0xfe, ...uint32ToBytes(n)];
    } else {
        return [0xff, ...uint64ToBytes(n)];
    }
}


const checkSegwit = (txn) => {
    return txn.vin.some(vin => vin.witness);
};


const calculateTransaction = (txn) => {
    if(checkSegwit(txn)) {
        return calculate_segwit_transaction(txn);
    }else {
        return calculate_non_segwit_transaction(txn);
    }
}


const calculate_non_segwit_transaction = (txn) => {
    let serializedResult = [];
    let transactionFee = 0;
    let inputValue = 0;
    let outputValue = 0;
    let weight = 0;

    const ver_bytes = Buffer.alloc(4);
    ver_bytes.writeUInt32LE(txn.version);
    serializedResult.push(...ver_bytes);

    const count_vin = BigInt(txn.vin.length);
    serializedResult.push(...serializeVarInt(count_vin));

    for (const vin of txn.vin) {
        inputValue += vin.prevout.value;

        const txid_bytes = Buffer.from(vin.txid, 'hex');
        serializedResult.push(...reversedBytes(txid_bytes));

        const vout_bytes = Buffer.alloc(4);
        vout_bytes.writeUInt32LE(vin.vout);
        serializedResult.push(...vout_bytes);

        const script_sig_size = BigInt(vin.scriptsig.length / 2);
        serializedResult.push(...serializeVarInt(script_sig_size));

        const script_sig_bytes = Buffer.from(vin.scriptsig, 'hex');
        serializedResult.push(...script_sig_bytes);

        const seq_bytes = Buffer.alloc(4)
        seq_bytes.writeUInt32LE(vin.sequence);
        serializedResult.push(...seq_bytes);
    }

    const output_count_bytes = BigInt(txn.vout.length);
    serializedResult.push(...serializeVarInt(output_count_bytes));

    for (const vout of txn.vout) {
        outputValue += vout.value;

        amountBytes = Buffer.alloc(8);
        amountBytes.writeBigUInt64LE(BigInt(vout.value));
        serializedResult.push(...amountBytes);

        const scriptPubKeyLengthBytes = BigInt(vout.scriptpubkey.length / 2);
        serializedResult.push(...serializeVarInt(scriptPubKeyLengthBytes));

        const scriptPubKeyBytes = Buffer.from(vout.scriptpubkey, 'hex');
        serializedResult.push(...scriptPubKeyBytes);
    }

    const locktime_bytes = Buffer.alloc(4);
    locktime_bytes.writeUInt32LE(txn.locktime);
    serializedResult.push(...locktime_bytes);

    transactionFee = inputValue - outputValue;
    weight += serializedResult.length * 4;
    return { serializedResult, transactionFee, weight };
}

const calculate_segwit_transaction = (txn) => {
    let serializedResult = [];
    let transactionFee = 0;
    let inputValue = 0;
    let outputValue = 0;
    let weight = 0;
    let witnessBytesLength = 0;

    const ver_bytes = Buffer.alloc(4);
    ver_bytes.writeUInt32LE(txn.version);
    serializedResult.push(...ver_bytes);
    weight += ver_bytes.length * 4;

    const marker_bytes = Buffer.alloc(1);
    marker_bytes.writeUInt8(0);
    serializedResult.push(...marker_bytes);
    weight += marker_bytes.length * 1;
    witnessBytesLength += marker_bytes.length * 1;

    const flag_bytes = Buffer.alloc(1);
    flag_bytes.writeUInt8(1);
    serializedResult.push(...flag_bytes);
    weight += flag_bytes.length * 1;
    witnessBytesLength += flag_bytes.length * 1;

    const count_vin = BigInt(txn.vin.length);
    serializedResult.push(...serializeVarInt(count_vin));
    weight += serializeVarInt(count_vin).length * 4;

    for (const vin of txn.vin) {
        inputValue += vin.prevout.value;

        const txid_bytes = Buffer.from(vin.txid, 'hex');
        serializedResult.push(...reversedBytes(txid_bytes));
        weight += txid_bytes.length * 4;

        const vout_bytes = Buffer.alloc(4);
        vout_bytes.writeUInt32LE(vin.vout);
        serializedResult.push(...vout_bytes);
        weight += vout_bytes.length * 4;

        const script_sig_size = BigInt(vin.scriptsig.length / 2);
        serializedResult.push(...serializeVarInt(script_sig_size));
        weight += serializeVarInt(script_sig_size).length * 4;

        const script_sig_bytes = Buffer.from(vin.scriptsig, 'hex');
        serializedResult.push(...script_sig_bytes);
        weight += script_sig_bytes.length * 4;

        const seq_bytes = Buffer.alloc(4)
        seq_bytes.writeUInt32LE(vin.sequence);
        serializedResult.push(...seq_bytes);
        weight += seq_bytes.length * 4;
    }

    const output_count_bytes = BigInt(txn.vout.length);
    serializedResult.push(...serializeVarInt(output_count_bytes));
    weight += serializeVarInt(output_count_bytes).length * 4;

    for (const vout of txn.vout) {
        outputValue += vout.value;

        amountBytes = Buffer.alloc(8);
        amountBytes.writeBigUInt64LE(BigInt(vout.value));
        serializedResult.push(...amountBytes);
        weight += amountBytes.length * 4;

        const scriptPubKeyLengthBytes = BigInt(vout.scriptpubkey.length / 2);
        serializedResult.push(...serializeVarInt(scriptPubKeyLengthBytes));
        weight += serializeVarInt(scriptPubKeyLengthBytes).length * 4;

        const scriptPubKeyBytes = Buffer.from(vout.scriptpubkey, 'hex');
        serializedResult.push(...scriptPubKeyBytes);
        weight += scriptPubKeyBytes.length * 4;
    }

    serializedResultBeforeWitness = serializedResult.length;
    for (const vin of txn.vin) {
        if (vin.witness) {
            const witnessCount = BigInt(vin.witness.length);
            serializedResult.push(...serializeVarInt(witnessCount));
            for (const witness of vin.witness) {
                const witnessBytes = Buffer.from(witness, 'hex');
                const witnessLength = BigInt(witnessBytes.length);
                const serializedVarInt = serializeVarInt(witnessLength);

                serializedResult.push(...serializedVarInt);

                const chunkSize = 1000;
                for (let i = 0; i < witnessBytes.length; i += chunkSize) {
                    const chunk = witnessBytes.slice(i, i + chunkSize);
                    serializedResult.push(...chunk);
                }
            }
        } else {
            serializedResult.push(0);
        }
    }

    serializedResultAfterWitness = serializedResult.length;
    WitnessContentLength = serializedResultAfterWitness - serializedResultBeforeWitness;

    weight += WitnessContentLength * 1;
    witnessBytesLength += WitnessContentLength * 1;

    const locktime_bytes = Buffer.alloc(4);
    locktime_bytes.writeUInt32LE(txn.locktime);
    serializedResult.push(...locktime_bytes);
    weight += locktime_bytes.length * 4;

    transactionFee = inputValue - outputValue;

    return { serializedResult, transactionFee, weight, witnessBytesLength };
}

function operation(parsed_array) {
    let feeArray = [];

    parsed_array.map((data) => {
        let finalWeight = 0;
        let { serializedResult, transactionFee, weight } = calculate_non_segwit_transaction(data);
        const serializedOut = serializedResult.map(byte => {
            return byte.toString(16).padStart(2, '0');
        }).join('');

        const txid1 = doubleSHA256(Buffer.from(serializedOut, 'hex'));
        txids.push(txid1);
        finalWeight += weight;

        if (checkSegwit(data)) {
            let { serializedResult, transactionFee, weight, witnessBytesLength } = calculate_segwit_transaction(data);

            const serializedOut = serializedResult.map(byte => {
                return byte.toString(16).padStart(2, '0');
            }).join('');
            finalWeight += witnessBytesLength;
            weight = finalWeight

            weightArray.push(weight);

            const txid = doubleSHA256(Buffer.from(serializedOut, 'hex'));
            txidArray.push(txid);


            const reversed_txids = reverseHex(txid1);
            txidReverse.push(reversed_txids);

            const fileName = singleSHA256(reversed_txids) + ".json"
            fileNameAfterOperation.push(fileName);

            feeArray.push(transactionFee);
            considerationArray.push({ fileName, txid: txid1, transactionFee, weight, wTxid: txid });
        }
        else {
            let { serializedResult, transactionFee, weight } = calculate_non_segwit_transaction(data);

            const serializedOut = serializedResult.map(byte => {
                return byte.toString(16).padStart(2, '0');
            }).join('');
            weightArray.push(weight);

            const txid = doubleSHA256(Buffer.from(serializedOut, 'hex'));
            txidArray.push(txid);


            const reversed_txids = reverseHex(txid);
            txidReverse.push(reversed_txids);

            const fileName = singleSHA256(reversed_txids) + ".json"
            fileNameAfterOperation.push(fileName);

            feeArray.push(transactionFee);
            considerationArray.push({ fileName, txid: txid, transactionFee, weight, wTxid: txid });
        }
    })
}

function fetchTransaction() {
    const folder = "./mempool";
    let count = 0;
    fs.readdirSync(folder).forEach(file => {
        fileArray.push(file);
        count++;
    }
    );

    let transactionArray = [];

    fileArray.map((files) => {
        let data = fs.readFileSync(`./mempool/${files}`, 'utf8')
        transactionArray.push(data);
    })

    const parsed_array = transactionArray.map(item => JSON.parse(item));
    return parsed_array;
}

function merkleRoot(txids) {
    if (txids.length === 1) {
        return txids[0];
    }

    const result = [];

    for (let i = 0; i < txids.length; i += 2) {
        const one = txids[i];
        const two = txids[i + 1] || one;
        const concat = one + two;

        result.push(doubleSHA256(concat));
    }

    return merkleRoot(result);
}

function wTxidCommitment(wtxid_final_array) {
    let wTxidArray = [];
    let coinbase_txid = "0000000000000000000000000000000000000000000000000000000000000000"
    wTxidArray.push(coinbase_txid);
    wTxidArray.push(...wtxid_final_array);
    const wTxidByteOrder = wTxidArray.map(x => x.match(/../g).reverse().join(''));
    const wTxidMerkleRoot = merkleRoot(wTxidByteOrder);

    return wTxidMerkleRoot;
}

function calculate_coinbase_txid(parsedData) {
    const data = parsedData;
    let weightFinal = 0;
    let wTxid = 0;
    let reversed_txids = 0;

    let { serializedResult, transactionFee, weight } = calculate_non_segwit_transaction(data);
    const serializedOut = serializedResult.map(byte => {
        return byte.toString(16).padStart(2, '0');
    }).join('');

    const txid1 = doubleSHA256(Buffer.from(serializedOut, 'hex'));
    weightFinal += weight;

    if (checkSegwit(data)) {
        let { serializedResult, transactionFee, weight, witnessBytesLength } = calculate_segwit_transaction(data);
        const serializedOut = serializedResult.map(byte => {
            return byte.toString(16).padStart(2, '0');
        }).join('');

        weightFinal += witnessBytesLength;
        weight = weightFinal;

        wTxid = doubleSHA256(Buffer.from(serializedOut, 'hex'));

        reversed_txids = reverseHex(txid1);
    }

    return { txid1, wTxid, weight, serializedOut };

}

function coinbase_transaction(fileArray, wtxid_final_array) {
    let block_Height = 840000;
    block_Height = block_Height.toString(16);
    block_Height = block_Height.padStart(6, '0');
    block_Height = reverseHex(block_Height);

    let netReward = 0;

    for (const files of fileArray) {
        let fee = 0;
        let input = 0;
        let output = 0;
        const data = fs.readFileSync(`./mempool/${files}`, 'utf8');
        const parsedData = JSON.parse(data);

        for (const vin of parsedData.vin) {
            input += vin.prevout.value;
        }
        for (const vout of parsedData.vout) {
            output += vout.value;
        }

        fee = input - output;
        netReward += fee;
    }

    netReward += (3.125 * 100000000);

    let commitmentHeader = "aa21a9ed";
    let witnessCommitment = wTxidCommitment(wtxid_final_array);

    let scriptpubkeysize = (4 + commitmentHeader.length + witnessCommitment.length);
    scriptpubkeysize = scriptpubkeysize / 2;
    scriptpubkeysize = scriptpubkeysize.toString(16);
    scriptpubkeysize = scriptpubkeysize.padStart(2, '0');

    const coinbaseTx = {
        "version": 1,
        "marker": "00",
        "flag": "01",
        "inputcount": "01",
        "vin": [
            {
                "txid": "0000000000000000000000000000000000000000000000000000000000000000",
                "vout": "ffffffff",
                "prevout": {
                    value: netReward
                },
                "scriptsigsize": "32",
                "scriptsig": "03" + block_Height + "135368726579612052616a204261676172696120256c0000946e0100",
                "witness": [
                    "0000000000000000000000000000000000000000000000000000000000000000",
                ],
                "sequence": "ffffffff"
            },
        ],
        "outputcount": "02",
        "vout": [
            {
                "value": netReward,
                "scriptpubkeysize": "19",
                "scriptpubkey": "76a91455ae51684c43435da751ac8d2173b2652eb6410588ac"
            },
            {
                "value": 0,
                "scriptpubkeysize": scriptpubkeysize,
                "scriptpubkey": "6a" + "24" + commitmentHeader + witnessCommitment, 
            }
        ],
        "witness": [{
            "stackitems": "01",
            "0": {
                "size": "20",
                "item": "0000000000000000000000000000000000000000000000000000000000000000"
            }
        }
        ],
        "locktime": "00000000",
    };

    const { txid1, wTxid, weight, serializedOut } = calculate_coinbase_txid(coinbaseTx);

    return { txid1, serializedOut };
}

function pre_mined_block() {
    const prevBlock_Hash = 0x00000000000000000000000000000000;

    let timestamp = Date.now();
    timestamp = timestamp / 1000;
    timestamp = timestamp.toString(16);
    timestamp = timestamp.padStart(4, '0');
    timestamp = timestamp.slice(0, 8);
    timestamp = reverseHex(timestamp);
    const bits = "1d00ffff";

    data = considerationArray
    data.sort((a, b) => (a.transactionFee / a.weight) - (b.transactionFee / b.weight));
    data.reverse();

    let txid_final_array = [];
    let wtxid_final_array = [];
    let consideredFiles = [];
    let weightCount = 0;
    let feeCount = 0;
    let cnt = 0;
    let capacity = 4000000;

    for (let i = 0; i < data.length; i++) {
        if (capacity > 1000) {
            weightCount += data[i].weight;
            txid_final_array.push(data[i].txid);
            wtxid_final_array.push(data[i].wTxid);
            consideredFiles.push(data[i].fileName);
            feeCount += data[i].transactionFee;
            cnt++;
            capacity -= data[i].weight;
        }
    }

    const { txid1, serializedOut } = coinbase_transaction(consideredFiles, wtxid_final_array);

    let txids = [];
    txids.push(txid1);
    txids.push(...txid_final_array);

    const txidsByteOrder = txids.map(x => x.match(/../g).reverse().join(''));

    const result = merkleRoot(txidsByteOrder);

    return { timestamp, bits, prevBlock_Hash, result, txid1, txids, serializedOut };
}

function block_mining(timestamp, bits, prevBlock_Hash, result, nonce) {

    const blockHeader = {
        "version": 0x00000007,
        "prevBlock_Hash": prevBlock_Hash,
        "merkleRoot": result,
        "timestamp": timestamp,
        "bits": bits,
        "nonce": nonce
    }

    const serializedBlockHeader = [];
    const ver_bytes = Buffer.alloc(4);
    ver_bytes.writeUInt32LE(blockHeader.version);
    serializedBlockHeader.push(...ver_bytes);

    const prevBlock_HashBytes = Buffer.alloc(32);
    prevBlock_HashBytes.writeUInt32LE(blockHeader.prevBlock_Hash);
    serializedBlockHeader.push(...prevBlock_HashBytes);

    const timestamp_Bytes = Buffer.alloc(4);
    timestamp_Bytes.writeUInt32LE(blockHeader.timestamp);
    serializedBlockHeader.push(...timestamp_Bytes);

    const bits_bytes = Buffer.alloc(4);
    bits_bytes.writeUInt32LE(blockHeader.bits);
    serializedBlockHeader.push(...bits_bytes);

    const nonce_bytes = Buffer.alloc(4);
    nonce_bytes.writeUInt32LE(blockHeader.nonce);
    serializedBlockHeader.push(...nonce_bytes);


    const serializedBlockHeaderHex = serializedBlockHeader.map(byte => {
        return byte.toString(16).padStart(2, '0');
    }
    ).join('');

    const blockHeaderHash = doubleSHA256(Buffer.from(serializedBlockHeaderHex, 'hex'));

    return blockHeaderHash;
}

function mined(timestamp, bits, prevBlock_Hash, result, nonce) {

    const blockHeader = {
        "version": 0x00000007,
        "prevBlock_Hash": prevBlock_Hash,
        "merkleRoot": result,
        "timestamp": timestamp,
        "bits": bits,
        "nonce": nonce
    }

    const serializedBlockHeader = [];
    const ver_bytes = Buffer.alloc(4);
    ver_bytes.writeUInt32LE(blockHeader.version);
    serializedBlockHeader.push(...ver_bytes);

    const prevBlock_HashBytes = Buffer.alloc(32);
    prevBlock_HashBytes.writeUInt32LE(blockHeader.prevBlock_Hash);
    serializedBlockHeader.push(...prevBlock_HashBytes); 

    const merkleRoot_Bytes = Buffer.alloc(32);
    merkleRoot_Bytes.writeUInt32LE(blockHeader.result);
    serializedBlockHeader.push(...merkleRoot_Bytes);

    const timestamp_Bytes = Buffer.alloc(4);
    timestamp_Bytes.writeUInt32LE(blockHeader.timestamp);
    serializedBlockHeader.push(...timestamp_Bytes);

    const bits_bytes = Buffer.alloc(4);
    bits_bytes.writeUInt32LE(blockHeader.bits);
    serializedBlockHeader.push(...bits_bytes);

    const nonce_bytes = Buffer.alloc(4);
    nonce_bytes.writeUInt32LE(blockHeader.nonce);
    serializedBlockHeader.push(...nonce_bytes);


    const serializedBlockHeaderHex = serializedBlockHeader.map(byte => {
        return byte.toString(16).padStart(2, '0');
    }
    ).join('');

    return serializedBlockHeaderHex;
}

function startMining() {
    const parsed_array = fetchTransaction();
    operation(parsed_array);
    let countWeight = 0;
    weightArray.map((weight) => {
        if (weight >= 4000) {
            countWeight++;
        }

    })

    const { timestamp, bits, prevBlock_Hash, result, txid1, txids, serializedOut } = pre_mined_block();

    let nonce = 0;
    let blockHeaderHash = block_mining(timestamp, bits, prevBlock_Hash, result, nonce);
    let difficulty_target = "0000ffff00000000000000000000000000000000000000000000000000000000";

    while (true) {
        if (blockHeaderHash < difficulty_target) {
            break;
        } else {
            nonce++;
            blockHeaderHash = block_mining(timestamp, bits, prevBlock_Hash, result, nonce);
        }
    }

    let blockHeaderSerializedHex = mined(timestamp, bits, prevBlock_Hash, result, nonce);

    fs.writeFileSync('output.txt', blockHeaderSerializedHex + '\n' + serializedOut + '\n');
    txids.forEach(txid => {
        fs.appendFileSync('output.txt', txid + '\n');
    });
    console.log("Block mined successfully");
}

startMining();

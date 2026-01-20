export interface StoredSafe {
    address: string;
    salt: string;
    name: string;
}

export interface LogEntry {
    msg: string;
    type: 'info' | 'success' | 'error';
    timestamp: string;
}

interface Transfer {
    type: string;
    value: string;
    tokenAddress: string | null;
    tokenInfo: any;
    from: string;
    to: string;
}

export interface SafeTx {
    txType: 'MULTISIG_TRANSACTION' | 'ETHEREUM_TRANSACTION' | 'MODULE_TRANSACTION';
    executionDate: string;
    to: string;
    value: string;
    data: string | null;
    isSuccessful?: boolean;
    transactionHash?: string;
    from?: string;
    transfers?: Transfer[];
}

export interface QueuedTx {
    safeAddress: string;
    hash: string;
    to: string;
    value: string;
    data: string;
    operation: 0 | 1; // 0 = Call, 1 = DelegateCall
    nonce: number;
    description: string;
}
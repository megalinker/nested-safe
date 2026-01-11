import { base, baseSepolia } from "viem/chains";

// 1. Determine Network Mode
export const NETWORK = import.meta.env.VITE_NETWORK === 'mainnet' ? 'mainnet' : 'sepolia';

// 2. Export Chain Object & ID
export const ACTIVE_CHAIN = NETWORK === 'mainnet' ? base : baseSepolia;
export const CHAIN_ID = ACTIVE_CHAIN.id;
export const CHAIN_ID_HEX = `0x${CHAIN_ID.toString(16)}`;

// 3. RPC Configuration
export const RPC_URL = NETWORK === 'mainnet'
  ? import.meta.env.VITE_RPC_URL_MAINNET
  : import.meta.env.VITE_RPC_URL_SEPOLIA;

const PIMLICO_API_KEY = import.meta.env.VITE_PIMLICO_API_KEY;
const PIMLICO_NETWORK_SLUG = NETWORK === 'mainnet' ? 'base' : 'base-sepolia';

export const BUNDLER_URL = `https://api.pimlico.io/v1/${PIMLICO_NETWORK_SLUG}/rpc?apikey=${PIMLICO_API_KEY}`;
export const PAYMASTER_URL = `https://api.pimlico.io/v2/${PIMLICO_NETWORK_SLUG}/rpc?apikey=${PIMLICO_API_KEY}`;

// 4. Contract Addresses

// USDC Address
export const USDC_ADDRESS = NETWORK === 'mainnet'
  ? "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
  : "0x036CbD53842c5426634e7929541eC2318f3dCF7e";

// Periodic Policy (V5 - Pointer Support)
export const PERIODIC_ERC20_POLICY = NETWORK === 'mainnet'
  ? "0x5385bEc5ee3B6dE5028777A82016E0019AcB6399" // New Mainnet
  : "0xEA4EE1eD11D73Bfd9E1E5e12EA2c762F76Cad084"; // New Testnet

// Constants common to both (Safe/Rhinestone Singletons)
export const SAFE_7579_ADAPTER_ADDRESS = "0x7579f2AD53b01c3D8779Fe17928e0D48885B0003";
export const SMART_SESSIONS_VALIDATOR_ADDRESS = "0x00000000008bdaba73cd9815d79069c247eb4bda";
export const ENTRYPOINT_0_7 = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
export const MULTI_SEND_ADDRESS = "0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526";
export const OWNABLE_VALIDATOR_ADDRESS = "0x000000000013fdb5234e4e3162a810f54d9f7e98";
export const VALUE_LIMIT_POLICY = "0x730DA93267E7E513e932301B47F2ac7D062abC83";
export const USAGE_LIMIT_POLICY = "0x1F34eF8311345A3A4a4566aF321b313052F51493";
export const SUDO_POLICY = "0x0000003111cD8e92337C100F22B7A9dbf8DEE301";
export const TIME_FRAME_POLICY = "0x8177451511dE0577b911C254E9551D981C26dc72";
export const ERC20_SPENDING_LIMIT_POLICY = "0x00000088D48cF102A8Cdb0137A9b173f957c6343";
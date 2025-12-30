import { createWalletClient, custom, type WalletClient } from 'viem';
import { ACTIVE_CHAIN, CHAIN_ID_HEX, RPC_URL, NETWORK } from '../config';

interface Window {
  phantom?: {
    ethereum?: any;
  };
  ethereum?: any;
}

export const connectPhantom = async (): Promise<WalletClient> => {
  const provider = (window as unknown as Window).phantom?.ethereum || (window as unknown as Window).ethereum;

  if (!provider) {
    throw new Error("Phantom wallet not found. Please install it.");
  }

  await provider.request({ method: 'eth_requestAccounts' });

  // Switch to Configured Chain (Base Sepolia or Mainnet)
  try {
    await provider.request({
      method: 'wallet_switchEthereumChain',
      params: [{ chainId: CHAIN_ID_HEX }],
    });
  } catch (switchError: any) {
    if (switchError.code === 4902) {
      // Define params dynamically based on config
      await provider.request({
        method: 'wallet_addEthereumChain',
        params: [
          {
            chainId: CHAIN_ID_HEX,
            chainName: NETWORK === 'mainnet' ? 'Base Mainnet' : 'Base Sepolia',
            nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 },
            rpcUrls: [RPC_URL],
            blockExplorerUrls: [ACTIVE_CHAIN.blockExplorers.default.url],
          },
        ],
      });
    }
  }

  const [account] = await provider.request({ method: 'eth_accounts' });

  if (!account) {
    throw new Error("No account found");
  }

  return createWalletClient({
    account,
    chain: ACTIVE_CHAIN, // Use config chain
    transport: custom(provider),
  });
};
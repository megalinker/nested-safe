import { createWalletClient, custom, type WalletClient } from 'viem';
import { baseSepolia } from 'viem/chains';

// Define the window interface to include Phantom
interface Window {
  phantom?: {
    ethereum?: any;
  };
  ethereum?: any;
}

export const connectPhantom = async (): Promise<WalletClient> => {
  // 1. Detect Provider
  const provider = (window as unknown as Window).phantom?.ethereum || (window as unknown as Window).ethereum;

  if (!provider) {
    throw new Error("Phantom wallet not found. Please install it.");
  }

  // 2. Request Access
  await provider.request({ method: 'eth_requestAccounts' });

  // 3. Switch to Base Sepolia (Chain ID 84532)
  try {
    await provider.request({
      method: 'wallet_switchEthereumChain',
      params: [{ chainId: '0x14a34' }], // 84532 in hex
    });
  } catch (switchError: any) {
    // This error code indicates that the chain has not been added to MetaMask/Phantom.
    if (switchError.code === 4902) {
      await provider.request({
        method: 'wallet_addEthereumChain',
        params: [
          {
            chainId: '0x14a34',
            chainName: 'Base Sepolia',
            nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 },
            rpcUrls: ['https://sepolia.base.org'],
            blockExplorerUrls: ['https://sepolia.basescan.org'],
          },
        ],
      });
    }
  }

  // 4. Get Account
  const [account] = await provider.request({ method: 'eth_accounts' });

  if (!account) {
    throw new Error("No account found");
  }

  // 5. Create Viem Client
  return createWalletClient({
    account, 
    chain: baseSepolia,
    transport: custom(provider),
  });
};
# 🪆 Nested Safe Engine (Base Sepolia)

A Next-Gen dApp that demonstrates **Recursive Account Abstraction**. This application allows a user to create a chain of Safe Smart Accounts starting from a Phantom Wallet, utilizing **ERC-4337**, **Pimlico Paymasters**, and the **Safe Protocol Kit V5**.

![License](https://img.shields.io/badge/license-MIT-blue.svg) ![React](https://img.shields.io/badge/React-18-blue) ![TypeScript](https://img.shields.io/badge/TypeScript-5-blue) ![Vite](https://img.shields.io/badge/Vite-5-purple)

## 🌟 Key Features

*   **Phantom Wallet Integration**: Connects using EIP-1193 provider injection.
*   **ERC-4337 Primary Safe**: Creates a counterfactual Safe Smart Account powered by **Permissionless.js**.
*   **Gasless Architecture**: All deployment and execution transactions are **sponsored** by Pimlico (Zero ETH required in EOA).
*   **Nested Safe Deployment**: Deploys a standard Safe where the **owner is the Primary Safe** (not the EOA).
*   **Full-Chain Verification**: Cryptographically verifies the ownership chain: `EOA -> Primary Safe -> Nested Safe`.
*   **Asset Dashboard**: View ETH & USDC balances on the Nested Safe.
*   **Authorized Transfers**: Send funds *from* the Nested Safe by executing a UserOperation through the Primary Safe.

## 🏗 Architecture

The app builds an ownership hierarchy:

```mermaid
graph TD
    A[Phantom Wallet (EOA)] -->|Signer| B(Primary Safe / ERC-4337)
    B -->|Owner| C(Nested Safe / Standard Safe)
    P[Pimlico Paymaster] -.->|Sponsors Gas| B
```

1.  **EOA:** Your Phantom wallet key. It only signs messages.
2.  **Primary Safe:** An Account Abstraction wallet controlled by your EOA. It executes transactions on Base Sepolia.
3.  **Nested Safe:** A vault owned entirely by the Primary Safe. To move funds here, the Primary Safe must authorize the transaction.

## 🛠 Tech Stack

*   **Framework:** React + Vite
*   **Language:** TypeScript
*   **Web3 Client:** [Viem](https://viem.sh/)
*   **Account Abstraction:** [Permissionless.js](https://docs.pimlico.io/permissionless)
*   **Infrastructure:** [Pimlico](https://pimlico.io/) (Bundler & Paymaster)
*   **Safe SDK:** [@safe-global/protocol-kit](https://docs.safe.global/sdk/protocol-kit) (V5)

## 🚀 Getting Started

### 1. Prerequisites

*   Node.js (v18+)
*   **Phantom Wallet** browser extension.
*   A **Pimlico API Key** (Get one for free [here](https://dashboard.pimlico.io/)).

### 2. Installation

Clone the repository and install dependencies.

```bash
git clone https://github.com/your-username/nested-safe-engine.git
cd nested-safe-engine

# Install dependencies
npm install
```

### 3. Environment Setup

Create a `.env` file in the root directory:

```bash
touch .env
```

Add your Pimlico API Key:

```env
VITE_PIMLICO_API_KEY=your_pimlico_api_key_here
# Optional: Override Base Sepolia RPC if needed
# VITE_BASE_SEPOLIA_RPC_URL=https://sepolia.base.org
```

### 4. Run the App

Start the development server:

```bash
npm run dev
```

Open `http://localhost:5173` in your browser.

## 📖 Usage Guide

The app guides you through a 5-step process:

1.  **Connect Phantom:** Links your browser wallet.
2.  **Initialize Primary Safe:** Calculates the address of your ERC-4337 Safe. *No transaction is sent yet.*
3.  **Deploy Nested Safe:**
    *   Generates the deployment payload for a new Safe.
    *   Sends a **User Operation** via Pimlico.
    *   **Result:** The Primary Safe is deployed, and it immediately deploys the Nested Safe. **Gas Cost: $0.**
4.  **Verify Ownership:** Checks on-chain data to confirm `getOwners()` on the Nested Safe returns the Primary Safe's address.
5.  **Dashboard:**
    *   View ETH and USDC balances.
    *   Send ETH from the Nested Safe to any address.
    *   *Note: Sending funds requires the EOA to sign a message, which authorizes the Primary Safe to execute the transfer on the Nested Safe.*

## ⚠️ Troubleshooting

**"Internal Error" or "Simulation Failed"**
*   Ensure your Pimlico API key is valid and supports Base Sepolia.
*   If testing without the Paymaster logic (custom code), ensure your Phantom wallet has Base Sepolia ETH.

**"Buffer is not defined"**
*   The Safe Protocol Kit requires Node.js polyfills. Ensure `vite-plugin-node-polyfills` is installed and configured in `vite.config.ts`.

**Balances not updating?**
*   Click the "Refresh" button on the dashboard. Indexers on testnets can sometimes be a few seconds behind.

## 📜 License

This project is open-source and available under the MIT License.
// Import ethers.js
const { ethers } = require('ethers');

// Generate a new random wallet
const wallet = ethers.Wallet.createRandom();

// Display the private key and address
console.log("Private Key:", wallet.privateKey);
console.log("Address:", wallet.address);

import { Wallet, getDefaultProvider, formatEther, parseEther } from 'ethers';
import fs from 'fs';
import path from 'path';
import bcrypt from 'bcryptjs';
import crypto from 'crypto-js';
import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import inquirer from 'inquirer';
import chalk from 'chalk';

const walletsPath = path.join(process.cwd(), 'wallets.json');
const secretPath = path.join(process.cwd(), '2fa_secret.json');
const passwordHashPath = path.join(process.cwd(), 'program_password_hash.json');

// Función para encriptar datos
function encrypt(data, password) {
  return crypto.AES.encrypt(data, password).toString();
}

// Función para desencriptar datos
function decrypt(data, password) {
  const bytes = crypto.AES.decrypt(data, password);
  return bytes.toString(crypto.enc.Utf8);
}

// Función para crear un nuevo 2FA
function generate2FA() {
  const secret = speakeasy.generateSecret({ length: 20 });
  fs.writeFileSync(secretPath, JSON.stringify(secret));

  qrcode.toString(secret.otpauth_url, { type: 'terminal' }, (err, url) => {
    console.log(url);
    console.log(`Código secreto: ${secret.base32}`);
    console.log('Escanea este código con tu aplicación 2FA.');
  });
}

// Función para verificar el token 2FA
function verify2FA(token) {
  if (!fs.existsSync(secretPath)) {
    console.error('2FA no está configurado. Debes configurarlo primero.');
    process.exit(1);
  }

  const secret = JSON.parse(fs.readFileSync(secretPath));
  return speakeasy.totp.verify({ secret: secret.base32, encoding: 'base32', token });
}

// Función para cargar wallets desde el archivo wallets.json
function loadWallets() {
  if (!fs.existsSync(walletsPath)) {
    return [];
  }

  const walletsData = fs.readFileSync(walletsPath, 'utf-8');
  return JSON.parse(walletsData);
}

// Función para guardar wallets en el archivo wallets.json
function saveWallets(wallets) {
  fs.writeFileSync(walletsPath, JSON.stringify(wallets, null, 2));
}

// Función para cargar una billetera desde el archivo wallets.json
function loadWallet(walletName, password) {
  const wallets = loadWallets();
  const walletData = wallets.find(wallet => wallet.name === walletName);

  if (!walletData) {
    console.error('Billetera no encontrada.');
    process.exit(1);
  }

  try {
    const decryptedWalletData = decrypt(walletData.encryptedPrivateKey, password);
    return new Wallet(decryptedWalletData);
  } catch (error) {
    console.error('Contraseña incorrecta o archivo de billetera corrupto.');
    process.exit(1);
  }
}

// Menú principal
async function mainMenu() {
  const choices = [
    { name: chalk.green('Crear billetera'), value: 'create-wallet' },
    { name: chalk.blue('Consultar saldo'), value: 'get-balance' },
    { name: chalk.yellow('Enviar ETH'), value: 'send' },
    { name: chalk.cyan('Modo desarrollador'), value: 'dev' },
    { name: chalk.red('Salir'), value: 'exit' },
  ];

  const { action } = await inquirer.prompt({
    type: 'list',
    name: 'action',
    message: chalk.blue('Selecciona una opción:'),
    choices,
  });

  if (action === 'create-wallet') {
    await createWallet();
  } else if (action === 'get-balance') {
    await getBalance();
  } else if (action === 'send') {
    await sendETH();
  } else if (action === 'dev') {
    await devMenu();
  } else if (action === 'exit') {
    console.log(chalk.green('Saliendo...'));
    process.exit(0);
  }

  await mainMenu(); // Volver al menú principal después de la acción
}

// Menú de desarrollador
async function devMenu() {
  const choices = [
    { name: chalk.red('Ver clave privada (requiere 2FA)'), value: 'view-private-key' },
    { name: chalk.magenta('Configurar 2FA'), value: 'setup-2fa' },
    { name: chalk.green('Importar billetera'), value: 'import-wallet' },
    { name: chalk.yellow('Volver al menú principal'), value: 'back' },
  ];

  const { action } = await inquirer.prompt({
    type: 'list',
    name: 'action',
    message: chalk.blue('Modo desarrollador:'),
    choices,
  });

  if (action === 'view-private-key') {
    await viewPrivateKey();
  } else if (action === 'setup-2fa') {
    generate2FA();
  } else if (action === 'import-wallet') {
    await importWallet();
  } else if (action === 'back') {
    await mainMenu();
  }

  await devMenu(); // Volver al menú de desarrollador después de la acción
}

// Crear una billetera
async function createWallet() {
  const { name, password } = await inquirer.prompt([
    { type: 'input', name: 'name', message: 'Introduce un nombre para tu billetera:' },
    { type: 'password', name: 'password', message: 'Establece una contraseña para esta billetera:', mask: '*' },
  ]);

  const wallet = Wallet.createRandom();

  const encryptedPrivateKey = encrypt(wallet.privateKey, password);

  const wallets = loadWallets();
  wallets.push({ name, encryptedPrivateKey, address: wallet.address });
  saveWallets(wallets);

  console.log(chalk.green('Billetera creada y encriptada con éxito.'));
  console.log(chalk.green(`Dirección de la billetera: ${wallet.address}`));
}

// Consultar saldo
async function getBalance() {
  const { walletName, password } = await inquirer.prompt([
    { type: 'input', name: 'walletName', message: 'Introduce el nombre de la billetera:' },
    { type: 'password', name: 'password', message: 'Introduce la contraseña de la billetera:', mask: '*' },
  ]);

  const wallet = loadWallet(walletName, password);

  const provider = getDefaultProvider('mainnet');
  const balance = await provider.getBalance(wallet.address);

  const balanceInEther = formatEther(balance);
  console.log(chalk.green(`Saldo de ${wallet.address}: ${balanceInEther} ETH`));
}

// Enviar ETH
async function sendETH() {
  const { walletName, password } = await inquirer.prompt([
    { type: 'input', name: 'walletName', message: 'Introduce el nombre de la billetera:' },
    { type: 'password', name: 'password', message: 'Introduce la contraseña de la billetera:', mask: '*' },
  ]);

  const wallet = loadWallet(walletName, password);

  const { address, amount } = await inquirer.prompt([
    { type: 'input', name: 'address', message: 'Introduce la dirección de destino:' },
    { type: 'input', name: 'amount', message: 'Introduce el monto a enviar en ETH:' },
  ]);

  const token = await prompt('Introduce tu código 2FA: ');
  if (!verify2FA(token)) {
    console.error(chalk.red('Código 2FA incorrecto.'));
    return;
  }

  const provider = getDefaultProvider('mainnet');
  const walletWithProvider = wallet.connect(provider);

  const tx = {
    to: address,
    value: parseEther(amount),
  };

  console.log(chalk.yellow(`Enviando ${amount} ETH a ${address}...`));
  const transaction = await walletWithProvider.sendTransaction(tx);
  console.log(chalk.green(`Transacción enviada: ${transaction.hash}`));
  await transaction.wait();
  console.log(chalk.green('Transacción confirmada.'));
}

// Ver clave privada
async function viewPrivateKey() {
  const { walletName, password } = await inquirer.prompt([
    { type: 'input', name: 'walletName', message: 'Introduce el nombre de la billetera:' },
    { type: 'password', name: 'password', message: 'Introduce la contraseña de la billetera:', mask: '*' },
  ]);

  const wallet = loadWallet(walletName, password);

  const token = await prompt('Introduce tu código 2FA: ');
  if (!verify2FA(token)) {
    console.error(chalk.red('Código 2FA incorrecto.'));
    return;
  }

  console.log(chalk.red.bold('Advertencia: No compartas tu clave privada con nadie.'));
  console.log(chalk.green(`Clave privada: ${wallet.privateKey}`));
}

// Importar una billetera
async function importWallet() {
  const { name, privateKey, password } = await inquirer.prompt([
    { type: 'input', name: 'name', message: 'Introduce un nombre para la billetera:' },
    { type: 'input', name: 'privateKey', message: 'Introduce la clave privada de la billetera:' },
    { type: 'password', name: 'password', message: 'Introduce una contraseña para esta billetera:', mask: '*' },
  ]);

  const wallet = new Wallet(privateKey);
  const encryptedPrivateKey = encrypt(wallet.privateKey, password);

  const wallets = loadWallets();
  wallets.push({ name, encryptedPrivateKey, address: wallet.address });
  saveWallets(wallets);

  console.log(chalk.green('Billetera importada y encriptada con éxito.'));
  console.log(chalk.green(`Dirección de la billetera: ${wallet.address}`));
}

// Prompt para contraseñas
async function promptPassword(message) {
  const { password } = await inquirer.prompt({
    type: 'password',
    name: 'password',
    message,
    mask: '*',
  });
  return password;
}

// Prompt genérico
async function prompt(message) {
  const { input } = await inquirer.prompt({
    type: 'input',
    name: 'input',
    message,
  });
  return input;
}

// Iniciar el programa con autenticación y 2FA
async function startProgram() {
  if (!fs.existsSync(passwordHashPath)) {
    const { password } = await inquirer.prompt({
      type: 'password',
      name: 'password',
      message: 'Configura una contraseña para el programa:',
      mask: '*',
    });

    const hashedPassword = bcrypt.hashSync(password, 10);
    fs.writeFileSync(passwordHashPath, hashedPassword);
    console.log(chalk.green('Contraseña del programa establecida con éxito.'));
  } else {
    const password = await promptPassword('Introduce la contraseña del programa:');
    const hashedPassword = fs.readFileSync(passwordHashPath, 'utf-8');

    if (!bcrypt.compareSync(password, hashedPassword)) {
      console.error(chalk.red('Contraseña incorrecta.'));
      process.exit(1);
    }
  }
  
  if (fs.existsSync(secretPath)) {
    const token = await prompt('Introduce tu código 2FA:');
    if (!verify2FA(token)) {
      console.error(chalk.red('Código 2FA incorrecto.'));
      process.exit(1);
    }
  }

  await mainMenu();
}

// Iniciar el programa
startProgram();

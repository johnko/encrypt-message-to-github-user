const fs = require('fs');
const forge = require('node-forge');

function decryptMessage() {
  const originalPrivateKeyFile = process.argv[2];
  const encryptedMessageBase64 = fs.readFileSync(process.argv[3], 'utf8').trim();

  const privateKeyFile = 'rsaprivatekey.tmp';
  fs.copyFileSync(originalPrivateKeyFile, privateKeyFile);

  // Convert the private key to PEM format using ssh-keygen
  const { execSync } = require('child_process');
  try {
    execSync(`ssh-keygen -p -m pem -N "" -f ${privateKeyFile} -q`);
  } catch (error) {
    console.error('Error converting private key to PEM format:', error);
    process.exit(1);
  }
  const privateKeyPem = fs.readFileSync(privateKeyFile, 'utf8').trim();

  if (!encryptedMessageBase64) {
    console.error('Please enter a ciphertext message to decrypt.');
    return;
  }

  if (!privateKeyPem) {
    console.error('Please enter the RSA private key for decryption.');
    return;
  }

  const forgePrivateKey = forge.pki.privateKeyFromPem(privateKeyPem);
  cipherObj = JSON.parse(encryptedMessageBase64);

  // decrypt encapsulated 16-byte secret key
  var kdf1 = new forge.kem.kdf1(forge.md.sha1.create());
  var kem = forge.kem.rsa.create(kdf1);
  var key = kem.decrypt(forgePrivateKey, Buffer.from(cipherObj.encapsulation, 'base64'), 16);

  // decrypt some bytes
  var decipher = forge.cipher.createDecipher('AES-GCM', key);
  decipher.start({ iv: Buffer.from(cipherObj.iv, 'base64'), tag: Buffer.from(cipherObj.tag, 'base64') });
  decipher.update(forge.util.createBuffer(Buffer.from(cipherObj.encrypted, 'base64')));
  var pass = decipher.finish();

  // pass is false if there was a failure (eg: authentication tag didn't match)
  if (pass) {
    const boundary = 'DECRYPTED MESSAGE';
    console.log(`-----BEGIN ${boundary}-----`);
    console.log(decipher.output.toString());
    console.log(`-----END ${boundary}-----`);
  } else {
    console.error('Decryption failed.');
  }
  // clean up the privateKeyFile file
  fs.unlinkSync(privateKeyFile);
}

decryptMessage();

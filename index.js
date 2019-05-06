var crypto = require('crypto');
const fs=require('fs');
const path = require('path');

function generate_key(){
	crypto.generateKeyPair('rsa', {
		modulusLength: 4096,
		publicKeyEncoding: {
		  type: 'spki',
		  format: 'pem'
		},
		privateKeyEncoding: {
		  type: 'pkcs8',
		  format: 'pem',
		  cipher: 'aes-256-cbc',
		  passphrase: 'top secret'
		}
	 }, (err, publicKey, privateKey) => {
		// Handle errors and use the generated key pair.
		fs.writeFileSync("public.pem", publicKey);
		fs.writeFileSync("private.pem", privateKey);
		console.log(publicKey);
		console.log(privateKey);
	 });
}

function encrypt(toEncrypt, relativeOrAbsolutePathToPublicKey) {
	const absolutePath = path.resolve(relativeOrAbsolutePathToPublicKey)
	const publicKey = fs.readFileSync(absolutePath, 'utf8')
	const buffer = Buffer.from(toEncrypt, 'utf8')
	const encrypted = crypto.publicEncrypt(publicKey, buffer)
	return encrypted.toString('base64')
 }

 function decrypt(toDecrypt, relativeOrAbsolutePathtoPrivateKey) {
	const absolutePath = path.resolve(relativeOrAbsolutePathtoPrivateKey)
	const privateKey = fs.readFileSync(absolutePath, 'utf8')
	const buffer = Buffer.from(toDecrypt, 'base64')
	const decrypted = crypto.privateDecrypt(
	  {
		 key: privateKey.toString(),
		 passphrase: '',
	  },
	  buffer,
	)
	return decrypted.toString('utf8')
 }
 /*
function encrypt(toEncrypt, relativeOrAbsolutePathToPublicKey) {
	const absolutePath = path.resolve(relativeOrAbsolutePathToPublicKey);
	const publicKey = fs.readFileSync(absolutePath, 'utf8');
	const buffer = Buffer.from(toEncrypt, 'utf8');
	const encrypted = crypto.publicEncrypt(publicKey, buffer);
	return encrypted.toString('base64');
 }

 function decrypt(toDecrypt, relativeOrAbsolutePathtoPrivateKey) {
	const absolutePath = path.resolve(relativeOrAbsolutePathtoPrivateKey);
	const privateKey = fs.readFileSync(absolutePath, 'utf8');
	const buffer = Buffer.from(toDecrypt, 'base64');

	const decrypted = crypto.privateDecrypt(
	  {
		 key: privateKey.toString(),
		 passphrase: '',
	  },
	  buffer,
	)
	//const decrypted = crypto.privateDecrypt(privateKey,buffer);
	return decrypted.toString('utf8');
 }
*/
const enc = encrypt('ftifti hoşgeldin', 'public.pem');
console.log('enc', enc);

const dec = decrypt(enc, 'private.pem');
console.log('dec', dec);
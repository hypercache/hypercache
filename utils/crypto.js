const crypto = require("crypto");

const hash = (str = "") => {
  if (str.trim() === "") {
    return hash(Math.random() + "" + new Date().getTime());
  } else {
    return crypto
      .createHash("sha256")
      .update(str)
      .digest("hex");
  }
};

/**
 * Encrypts text by given key
 * @param String text to encrypt
 * @param Buffer masterkey
 * @returns String encrypted text, base64 encoded
 */
const encrypt = (text, masterkey) => {
  // random initialization vector
  const iv = crypto.randomBytes(16);

  // random salt
  const salt = crypto.randomBytes(64);

  // derive encryption key: 32 byte key length
  // in assumption the masterkey is a cryptographic and NOT a password there is no need for
  // a large number of iterations. It may can replaced by HKDF
  // the value of 2145 is randomly chosen!
  const key = crypto.pbkdf2Sync(masterkey, salt, 2145, 32, "sha512");

  // AES 256 GCM Mode
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  // encrypt the given text
  const encrypted = Buffer.concat([
    cipher.update(text, "utf8"),
    cipher.final()
  ]);

  // extract the auth tag
  const tag = cipher.getAuthTag();

  // generate output
  return Buffer.concat([salt, iv, tag, encrypted]).toString("base64");
};

/**
 * Decrypts text by given key
 * @param String base64 encoded input data
 * @param Buffer masterkey
 * @returns String decrypted (original) text
 */
const decrypt = (encdata, masterkey) => {
  // base64 decoding
  const bData = Buffer.from(encdata, "base64");

  // convert data to buffers
  const salt = bData.slice(0, 64);
  const iv = bData.slice(64, 80);
  const tag = bData.slice(80, 96);
  const text = bData.slice(96);

  // derive key using; 32 byte key length
  const key = crypto.pbkdf2Sync(masterkey, salt, 2145, 32, "sha512");

  // AES 256 GCM Mode
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);

  // encrypt the given text
  const decrypted =
    decipher.update(text, "binary", "utf8") + decipher.final("utf8");

  return decrypted;
};

const pair = async (pass = null) => {
  pass = pass || hash();

  return new Promise(resolve => {
    crypto.generateKeyPair(
      "rsa",
      {
        modulusLength: 4096,
        publicKeyEncoding: {
          type: "spki",
          format: "pem"
        },
        privateKeyEncoding: {
          type: "pkcs8",
          format: "pem",
          cipher: "aes-256-cbc",
          passphrase: pass
        }
      },
      (err, publicKey, privateKey) => {
        // Handle errors and use the generated key pair.
        if (err) {
          throw Error(err);
        }
        resolve({ pub: publicKey, priv: privateKey, pass });
      }
    );
  });
};

const sign = (priv, pass, data) => {
  const signer = crypto.createSign("sha256");
  signer.update(data);
  signer.end();
  console.log("in sign", data);

  const signature = signer.sign({ key: priv, passphrase: pass });
  return signature.toString("hex");
};

const verify = (pub, data, signature) => {
  const verifier = crypto.createVerify("sha256");
  verifier.update(data);
  verifier.end();
  return verifier.verify(pub, signature, "hex");
};

const uuid = () => {
  return (
    crypto.randomBytes(16).toString("hex") +
    "-" +
    crypto.randomBytes(16).toString("hex")
  );
};
// (async () => {
//   let example = "This is a piece of text";

//   // create key
//   let key = hash();

//   // encrypt
//   const enc = encrypt(example, key);

//   // decrypt
//   const dec = decrypt(enc, key);

//   //compare
//   console.log(example, dec);
//   console.log(example === dec);

//   const pair1 = await pair("my secret");
// })();

module.exports = {
  hash,
  encryptSym: encrypt,
  decryptSym: decrypt,
  pair,
  uuid,
  sign,
  verify
};

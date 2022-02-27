import * as crypto from "crypto";

export const encrypt = (text: string, key: string, iv: string) => {
  let cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return encrypted;
}

export const decrypt = (text: string, key: string, iv: string) => {
  let decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(text, 'base64', 'utf8');
  return (decrypted + decipher.final('utf8'));
}

export const hashPassword = (password: string, key: string) => {
  const sha256Hasher = crypto.createHmac("sha256", key);
  return sha256Hasher.update(password).digest("hex");
}

export const encryptHex = (text: string, key: string, iv: string) => {
  const cipher = crypto.createCipheriv('des-ecb', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

export const decryptHex = (text: string, key: string, iv: string) => {
  const decipher = crypto.createDecipheriv('des-ecb', key, iv);
  let decrypted = decipher.update(text, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted
}

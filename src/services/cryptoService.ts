import * as crypto from "crypto";

module.exports = {
  encrypt: (text: string, key: string) => {
    const cipher = crypto.createCipher("aes-256-cbc", key);
    let result = cipher.update(text, "utf8", "hex");
    result += cipher.final("hex");
    return result;
  },
  decrypt: (text: string, key: string) => {
    const decipher = crypto.createDecipher("aes-256-cbc", key);
    let result = decipher.update(text, "hex", "utf8");
    result += decipher.final("utf8");
    return result;
  },
}

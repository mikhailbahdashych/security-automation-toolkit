const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

const pathToKeys = path.resolve(__dirname, "../../keys");

module.exports = {
  sign(payload: string) {
    const cert = fs.readFileSync(`${pathToKeys}/private.pem`);
    return jwt.sign(
      payload,
      {
        key: cert,
        passphrase: process.env.JWT_PASSPHRASE
      },
      {
        algorithm: "RS256",
        expiresIn: "30m"
      }
    )
  },
  getUserPromise(token: string) {
    return new Promise((resolve, reject) => {
      jwt.verify(token, fs.readFileSync(`${pathToKeys}/public.pem`), (err: any, decoded: any) => {
        if(!err) {
          return resolve(decoded);
        } else {
          return reject(err);
        }
      })
    })
  },
  async getUser (token: string) {
    return await this.getUserPromise(token)
  }
}

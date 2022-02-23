import jwt from "jsonwebtoken";
import fs from 'fs';
import path from 'path';

import { JwtPayload } from "../interfaces/jwt";

const privateKey = fs.readFileSync(path.resolve(__dirname + "../../../keys/private.pem"));
const publicKey = fs.readFileSync(path.resolve(__dirname + "../../../keys/public.pem"));

export const sign = (payload: JwtPayload) => {
  try {
    return jwt.sign(
      payload,
      {
        key: privateKey,
        passphrase: process.env.JWT_PASSPHRASE.toString()
      },
      {
        algorithm: "RS256",
        expiresIn: "30m"
      }
    )
  } catch (e) {
    //
  }
}


export const getUser = async (token: string) => {
  try {
    return jwt.verify(
      token,
      publicKey
    ) as JwtPayload
    // @ts-ignore
    // return await this.getUserPromise(token)
  } catch (e) {
    //
  }
}


export const getUserPromise = (token: string) => {
  try {
    return new Promise(((resolve, reject) => {
      jwt.verify(token, publicKey, (err: any, decoded: any) => {
        if (!err) {
          return resolve(decoded);
        } else {
          return reject(err);
        }
      })
    }))
  } catch (e) {
    //
  }
}

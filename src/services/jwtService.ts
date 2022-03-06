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
        expiresIn: "6h"
      }
    )
  } catch (e) {
    //
  }
}


export const getClient = async (token: string) => {
  try {
    return jwt.verify(
      token,
      publicKey
    ) as JwtPayload
  } catch (e) {
    //
  }
}


export const getClientPromise = (token: string) => {
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

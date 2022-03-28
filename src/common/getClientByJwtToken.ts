import * as jwtService from "../services/jwtService";
import * as cryptoService from "../services/cryptoService";
import * as clientService from "../services/clientService";
import * as dotenv from 'dotenv';
dotenv.config();

export const getClientByJwtToken = async (jwt: string) => {
  const userJwt = await jwtService.getClient(jwt)
  if (!userJwt) return false
  const clientId = cryptoService.decrypt(userJwt.uxd, process.env.CRYPTO_KEY.toString(), process.env.CRYPTO_IV.toString())
  return await clientService.getClientByEmailOrId({ id: clientId })
}

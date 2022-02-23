import * as jwtService from './../services/jwtService';
import { Request, Response } from 'express';
import { CommonResponse } from "../responses/response";

export default async (req: Request, res: Response, next: any) => {
  try {
    if (req.headers.authorization) {
      const user = await jwtService.getUser(req.headers.authorization.split(' ')[1])
      if (user) {
        next()
      }
      else {
        return CommonResponse.common.unauthorized({res})
      }
    } else {
      return CommonResponse.common.unauthorized({ res })
    }
  } catch (e) {
    return CommonResponse.common.unauthorized({res});
  }
}

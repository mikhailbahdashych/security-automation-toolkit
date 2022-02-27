import { validationResult } from 'express-validator'
import { Request, Response } from "express";

export default (fields: any) => {
  return async (req: Request, res: Response, next: any) => {
    for (const field of fields) {
      await require(`./validators/${field}`)(req);
    }
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
}

import * as validator from 'express-validator'

export default (fields: any) => {
  return async (req: any, res: any, next: any) => {
    for (const field of fields) {
      await require(`./validators/${field}`)(req);
    }
    const errors = validator.validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
}
// exports.reqValidator = (fields) => {
//   return async (req, res, next) => {
//     for (const field of fields) {
//       await require(`./validators/${field}`)(req);
//     }
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       return res.status(400).json({ errors: errors.array() });
//     }
//     next();
//   };
// };

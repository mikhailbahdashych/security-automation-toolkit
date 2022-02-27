const nodeoutlook = require('nodejs-nodemailer-outlook')
const dotenv = require('dotenv')
dotenv.config()

import loggerConfig from '../common/logger'
const logger = loggerConfig({ label: 'email-controller', path: 'email' })

export const sendEmail = async (message: string) => {
  try {
    await nodeoutlook.sendEmail({
      auth: {
        user: process.env.EMAIL_NO_REPLY,
        pass: process.env.EMAIL_NO_REPLY_PASSWORD
      },
      from: process.env.EMAIL_NO_REPLY,
      to: "",
      subject: '',
      html: ``,
      text: '!',
    })
    logger.info(`Email was successfully sent`)
  } catch (e) {
    logger.info(`Inner error while sending email`)
  }
}

const nodemailer = require('nodemailer')
import loggerConfig from '../common/logger'
const logger = loggerConfig({ label: 'email-controller', path: 'email' })

export const sendEmail = async (message: string) => {
  const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
      user: '',
      pass: ''
    }
  });

  await transporter.sendMail({
    from: '"Fred Foo 👻" <>',
    to: "",
    subject: "Hello ✔",
    text: "Hello world?",
    html: "<b>Hello world?</b>",
  }).then(() => {
    logger.info(`Email was successfully sent.`)
  }).catch(() => {
    logger.info(`Inner error while sending email.`)
  })
}

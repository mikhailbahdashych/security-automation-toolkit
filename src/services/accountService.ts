const knex = require('../knex/knex.js')

export const getUserToLogin = async (email: string, password: string) => {
  return knex('users')
    .first()
    .where('email', email)
    .andWhere('password', password)
}

export const getUserByEmail = async (email: string) => {
  return knex('users')
    .first()
    .where('email', email)
}

export const getUserById = async (id: string) => {
  return knex('users')
    .first()
    .where('id', id)
}

export const createUser = async (data: object) => {
  return knex('users')
    .insert(data)
}

export const set2fa = async (data: { secret: string, clientId: string }) => {
  return knex('users')
    .update({two2fa: data.secret})
    .where('id', data.clientId)
}

export const get2fa = async (id: string) => {
  return knex('users')
    .first('two2fa')
    .where('id', id)
}

export const closeAccount = async (user: { id: string, email: string }) => {
  return knex('users')
    .update({
      email: `${user.email}_del`
    })
    .where('id', user.id)
}

export const changePassword = async (id: string, newPassword: string) => {
  return knex('users')
    .update({
      password: newPassword
    })
    .where('id', id)
}

export const changeEmail = async (id: string, newEmail: string) => {
  return knex('users')
    .update({
      email: newEmail
    })
    .where('id', id)
}

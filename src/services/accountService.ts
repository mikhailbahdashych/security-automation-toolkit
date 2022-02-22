const knex = require('../knex/knex')

module.exports = {
  async getUserToLogin(email: string, password: string) {
    return knex('users')
      .first()
      .where('email', email)
      .andWhere('password', password)
  },
  async getUserByEmail(email: string) {
    return knex('users')
      .first()
      .where('email', email)
  },
  async createUser(data: object) {
    return knex('users')
      .insert(data)
  },
  async set2fa(data: { token: string, clientId: string }) {
    return knex('users')
      .update({two2fa: data.token})
      .where('id', data.clientId)
  }
}

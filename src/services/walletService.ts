const knex = require('../knex/knex.js')
const tableName = 'balances'

export const getWalletsByClientId = async (id: string) => {
  return knex(tableName)
    .select('*')
    .where('clientid', id)
}

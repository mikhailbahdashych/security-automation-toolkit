exports.up = function(knex) {
  return knex.schema.alterTable('users', table => {
    table.text('two2fa').nullable()
  })
};

exports.down = function(knex) {
  return knex.schema.alterTable('users', table => {
    table.dropColumn('two2fa')
  })
};

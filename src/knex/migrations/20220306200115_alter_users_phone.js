exports.up = function(knex) {
  return knex.schema.alterTable('users', table => {
    table.text('phone').nullable()
  })
};

exports.down = function(knex) {
  return knex.schema.alterTable('users', table => {
    table.dropColumn('phone')
  })
};

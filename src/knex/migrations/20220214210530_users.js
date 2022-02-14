exports.up = function(knex) {
  return knex.schema.createTable('users', table => {
    table.uuid('id')
  })
};


exports.down = function(knex) {
  return knex.schema.dropTable('users')
};

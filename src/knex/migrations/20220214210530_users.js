exports.up = function(knex) {
  return knex.schema.createTable('users', table => {
    table.uuid('id').notNullable().defaultTo(knex.raw('gen_random_uuid ()')).primary()
    table.text('email').notNullable()
    table.text('password').notNullable()

    table.timestamp("created_at").defaultTo(knex.fn.now())
    table.timestamp("updated_at").defaultTo(knex.fn.now())

  })
};

exports.down = function(knex) {
  return knex.schema.dropTable('users')
};

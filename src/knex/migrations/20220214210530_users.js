exports.up = function(knex) {
  return knex.schema.createTable('clients', table => {
    table.uuid('id').notNullable().defaultTo(knex.raw('gen_random_uuid ()')).primary()
    table.text('personaluuid')
    table.text('email').notNullable()
    table.boolean('confirmemail').notNullable().defaultTo(false)
    table.boolean('emailchange').notNullable().defaultTo(false)
    table.text('password').notNullable()
    table.text('phone').nullable()
    table.text('phonecode').nullable()
    table.text('twofa').nullable()

    table.timestamp("createdat").defaultTo(knex.fn.now())
    table.timestamp("updatedat").defaultTo(knex.fn.now())

  })
};

exports.down = function(knex) {
  return knex.schema.dropTable('clients')
};

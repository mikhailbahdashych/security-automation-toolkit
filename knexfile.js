const dotenv = require('dotenv');
dotenv.config();

module.exports = {
  development: {
    client: 'pg',
    connection: {
      host: process.env.DB_HOST,
      user: process.env.DB_USERNAME,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_DATABASE,
      port: process.env.DB_PORT
    },
    migrations: {
      tableName: 'knex_migrations',
      directory: __dirname + '/src/knex/migrations'
    },
    debug: false,
  },
  production: {
    client: 'pg',
    connection: {
      host: process.env.DB_HOST,
      user: process.env.DB_USERNAME,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_DATABASE,
      port: process.env.DB_PORT
    },
    migrations: {
      tableName: 'knex_migrations',
      directory: __dirname + '/src/knex/migrations'
    },
    debug: false,
  }

};

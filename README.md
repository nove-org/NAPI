<h1 align="center">NAPI</h1>

Full-featured API that handles most of the Nove projects. Including: OAuth2, account administration and more. Required to run certain projects such as Files: [files.backend](https://github.com/nove-org/files.backend), [files.frontend](https://github.com/nove-org/files.frontend).

<br />

## Setting up the environment
1. To start please install following packages `nodejs`, `yarn`, `imagemagick`, `postgresql`, `libwebp`<br/><br/>
   You can do this on Arch Linux by using Paru package manager
   ```yml
   paru -S nodejs yarn imagemagick postgresql libwebp
   ```
2. Fork and then `git clone` your forked repository
3. Install required node packages using `yarn` command
4. Set up PostgreSQL and then run `yarn db`. Before running database generate and update please fill out the *.env* file using premade *.env.example*
5. If everything was successful you are ready to go! Happy coding.

## Start the project
NAPI project comes with premade commands for simplified usage:
 - `yarn dev`: In development mode, compiles Sass in watch mode and the project itself, running in nodemon
 - `yarn dev:sass`: Watch for Sass file changes and compile them to CSS directory
 - `yarn build`: Compile the project
 - `yarn build:sass`: Compile Sass files to CSS
 - `yarn start`: Start the project (auto compilation)
 - `yarn db`: Prepare database for the project (generate and update)
 - `yarn db:generate`: Generate Prisma Package
 - `yarn db:update`: Sync Prisma with PostgreSQL (required config in *.env* and PostgreSQL running)
 - `yarn db:studio`: Start Prisma Studio on localhost:5555
 - `yarn test`: Run project tests

## For developers

### Commit messages
All commits in pull request or not have to follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/#specification) guidelines. Otherwise, they will be rejected instantly.

### PostgreSQL
Before you will be able to use NAPI you have to setup PostgreSQL as your database. Download it from [here](https://www.postgresql.org/download/) (or using your package manager) and follow the setup guide.

1. Connect to PostgreSQL
2. Create new user with password
3. Create new database called `napi` on that user
4. Give user all privileges on that database
5. Give user privileges to create [shadow databases](https://www.prisma.io/docs/concepts/components/prisma-migrate/shadow-database#shadow-database-user-permissions)

In the *.env* file
```env
DATABASE_URL="postgres://USERNAME:PASSWORD@localhost:5432/DATABASE"
```

You should now be able to setup Prisma

```yml
# Generate Prisma Client
yarn db:generate
# Keep your database schema in sync with your Prisma schema as it evolves
yarn db:update
```

## License
This project is licensed under [GNU Affero General Public License v3.0](https://github.com/nove-org/NAPI/blob/main/LICENSE)

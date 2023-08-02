<h1 align="center">NAPI</h1>

Full-featured API that handles most of the Nove projects. Including: OAuth2, account administration and more. Required to run certain projects such as Files: [files.backend](https://github.com/nove-org/files.backend), [files.frontend](https://github.com/nove-org/files.frontend).

<br />

## Setting up the environment
1. To get started, please install the following packages `nodejs`, `yarn`, `imagemagick`, `postgresql`, `libwebp`<br/><br/>
   ```yml
   # Example of installing the packages on Arch Linux using Paru package manager
   paru -S nodejs yarn imagemagick postgresql libwebp
   ```
2. Fork and then `git clone` your forked repository
   ```yml
   # You should always clone repositories through SSH
   git clone git@github.com:nove-org/NAPI.git
   ```
3. Install the required node packages
   ```yml
   # Always use yarn as your package manager when contributing to nove-org projects
   yarn
   
   # If the command wasn't found please install yarn >=1.22.19 package manager
   # You can do it on Arch Linux using the following command
   paru -S yarn
4. Set up PostgreSQL and then run `yarn db`. Before running database generate and update please fill out the *.env* file using premade *.env.example*
   ```yml
   yarn db
   # Alternatively, you can use following commands
   yarn db:generate
   yarn db:update
   ```
5. If everything was successful you are ready to go! Happy coding.

## Scripts in package.json
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

## Contributing
Feel free to contribute improvements, features, bug fixes and more to our code. When you do that, please follow the guidelines. Found a bug in this file? Fork this repository, fix it and open a new pull request.

### Commit messages
All commits in pull request or not have to follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/#specification) guidelines. Otherwise, they will be rejected instantly.

### Formatting
The code should be automatically formatted after you create your pull request with our config file. You can still install Prettier extension for VSCode/VSCodium and turn on format on save.

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

You should now be able to setup Prisma.

```yml
# Generate Prisma Client
yarn db:generate
# Keep your database schema in sync with your Prisma schema as it evolves
yarn db:update
```

## License
This project is under the [GNU Affero General Public License v3.0](https://github.com/nove-org/NAPI/blob/main/LICENSE)

# NAPI - Nove API
Main API project for all Nove products

## Setting up the environment
1. To start please install following packages `nodejs`, `yarn`, `imagemagick`, `postgresql`, `libwebp`<br/><br/>
   You can do this on Arch Linux by using Paru package manager
   ```sh
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

## Commit messages
All commits have to follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/#specification) guidelines. Otherwise, they will be rejected instantly.

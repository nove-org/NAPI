/*
  Warnings:

  - Added the required column `password` to the `User` table without a default value. This is not possible if the table is not empty.
  - Made the column `username` on table `User` required. This step will fail if there are existing NULL values in that column.

*/
-- AlterTable
ALTER TABLE "User" ADD COLUMN     "password" TEXT NOT NULL,
ALTER COLUMN "username" SET NOT NULL;

-- CreateTable
CREATE TABLE "OAuth_App" (
    "client_id" TEXT NOT NULL,
    "client_secret" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "link_homepage" TEXT NOT NULL,
    "owner" TEXT NOT NULL,
    "link_privacy_policy" TEXT NOT NULL,
    "link_tos" TEXT NOT NULL,
    "redirect_uris" TEXT[],
    "isVerified" BOOLEAN NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "OAuth_App_pkey" PRIMARY KEY ("client_id")
);

-- CreateTable
CREATE TABLE "OAuth_Authorization" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "app_id" TEXT NOT NULL,
    "scopes" TEXT[],
    "redirect_uri" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "refresh_token" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "OAuth_Authorization_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "OAuth_Authorization" ADD CONSTRAINT "OAuth_Authorization_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OAuth_Authorization" ADD CONSTRAINT "OAuth_Authorization_app_id_fkey" FOREIGN KEY ("app_id") REFERENCES "OAuth_App"("client_id") ON DELETE RESTRICT ON UPDATE CASCADE;

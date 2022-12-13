/*
  Warnings:

  - You are about to drop the `oAuth_Code` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "oAuth_Code" DROP CONSTRAINT "oAuth_Code_app_id_fkey";

-- DropForeignKey
ALTER TABLE "oAuth_Code" DROP CONSTRAINT "oAuth_Code_user_id_fkey";

-- DropTable
DROP TABLE "oAuth_Code";

-- CreateTable
CREATE TABLE "OAuth_Code" (
    "code" TEXT NOT NULL,
    "app_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "scopes" TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "OAuth_Code_pkey" PRIMARY KEY ("code")
);

-- AddForeignKey
ALTER TABLE "OAuth_Code" ADD CONSTRAINT "OAuth_Code_app_id_fkey" FOREIGN KEY ("app_id") REFERENCES "OAuth_App"("client_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OAuth_Code" ADD CONSTRAINT "OAuth_Code_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

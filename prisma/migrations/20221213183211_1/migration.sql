-- AlterTable
ALTER TABLE "User" ALTER COLUMN "token" DROP DEFAULT;

-- CreateTable
CREATE TABLE "oAuth_Code" (
    "code" TEXT NOT NULL,
    "app_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "scopes" TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "oAuth_Code_pkey" PRIMARY KEY ("code")
);

-- AddForeignKey
ALTER TABLE "oAuth_Code" ADD CONSTRAINT "oAuth_Code_app_id_fkey" FOREIGN KEY ("app_id") REFERENCES "OAuth_App"("client_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oAuth_Code" ADD CONSTRAINT "oAuth_Code_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

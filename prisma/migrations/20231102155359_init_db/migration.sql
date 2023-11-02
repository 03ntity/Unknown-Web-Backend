-- CreateTable
CREATE TABLE "users" (
    "id" SERIAL NOT NULL,
    "email" TEXT NOT NULL,
    "password" TEXT,
    "username" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "emailVerified" BOOLEAN DEFAULT false,
    "firstName" TEXT,
    "lastName" TEXT,
    "passwordResetToken" TEXT,
    "provider" TEXT DEFAULT 'email',
    "providerId" TEXT,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "verifyToken" TEXT,
    "profileImage" TEXT,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE UNIQUE INDEX "users_username_key" ON "users"("username");

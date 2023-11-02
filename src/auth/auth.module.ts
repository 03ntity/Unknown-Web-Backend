import { Module } from '@nestjs/common';
import { PrismaModule } from "../prisma/prisma.module";
import { AuthService } from "./auth.service";
import { JwtModule } from "@nestjs/jwt";
import { AuthController } from "./auth.controller";
import { JwtStrategy } from "./strategy/jwt.strategy";
import { GoogleStrategy } from "./strategy/google.strategy";
import {GithubStrategy} from "./strategy/github.strategy";

@Module({
    imports: [PrismaModule, JwtModule.register({
        global: true,
        signOptions: { expiresIn: '60m' },
    }),
    ],
    controllers: [AuthController],
    providers: [AuthService, JwtStrategy, GoogleStrategy, GithubStrategy],
})
export class AuthModule {}

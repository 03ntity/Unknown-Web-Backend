import { Module } from '@nestjs/common';
import { PrismaModule } from "../prisma/prisma.module";
import { AuthService } from "./auth.service";
import { JwtModule } from "@nestjs/jwt";
import { AuthController } from "./auth.controller";
import { JwtStrategy } from "./strategies/jwt.strategy";
import { GoogleStrategy } from "./strategies/google.strategy";
import { GithubStrategy } from "./strategies/github.strategy";
import {RtStrategy} from "./strategies/rt.strategy";


@Module({
    imports: [PrismaModule, JwtModule.register({
        global: true,
        signOptions: { expiresIn: '60m' },
    }),
    ],
    controllers: [AuthController],
    providers: [AuthService, JwtStrategy, RtStrategy, GoogleStrategy, GithubStrategy],
})
export class AuthModule {}

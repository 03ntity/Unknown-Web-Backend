import {Global, Module} from '@nestjs/common';
import {PrismaService} from "./prisma.service";
import {JwtService} from "@nestjs/jwt";

@Global()
@Module({
    providers: [PrismaService],
    exports: [PrismaService],
})
export class PrismaModule {}

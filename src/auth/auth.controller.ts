import { Controller, Post, Body, Get, UseGuards, Req, Res} from '@nestjs/common';
import { AuthService } from "./auth.service";
import { RegisterAuthDto } from "./dto/register-auth.dto";
import { LoginAuthDto } from "./dto/login-auth.dto";
import { AuthGuard } from "@nestjs/passport";
import {GoogleAuthDto} from "./dto/google-auth.dto";

@Controller('auth')
export class AuthController {
    constructor(private authService : AuthService) {}

    @Post('register')
    async register(@Body() request : RegisterAuthDto) {
        return this.authService.register(request);
    }

    @Post('login')
    async login(@Body() request : LoginAuthDto) {
        return this.authService.login(request);
    }

    @Get('google')
    @UseGuards(AuthGuard('google'))
    async googleLogin(@Req() req : Request) {}

    @Get('google/callback')
    @UseGuards(AuthGuard('google'))
    googleLoginRedirect(@Req() req)  {
        return this.authService.googleLogin(req);
    }

    @Get('github')
    @UseGuards(AuthGuard('github'))
    async githubLogin(@Req() req : Request) {}

    @Get('github/callback')
    @UseGuards(AuthGuard('github'))
    githubLoginRedirect(@Req() req)  {
        return this.authService.githubLogin(req);
    }

}

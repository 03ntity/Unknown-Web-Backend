import { Controller, Post, Body, Get, UseGuards, Req, Res} from '@nestjs/common';
import { AuthService } from "./auth.service";
import { RegisterAuthDto } from "./dto/register-auth.dto";
import { LoginAuthDto } from "./dto/login-auth.dto";
import { Request , Response } from 'express';
import { GithubGuard, GoogleGuard } from "./guard";
import {JwtRtGuard} from "./guard/rt.guard";
import { GetCurrentUserId } from "./decorators/get-current-user-id.decorator";
import { GetCurrentUser } from "./decorators/get-current-user.decorator";

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


    @UseGuards(JwtRtGuard)
    @Post('refresh')
    refreshTokens(@GetCurrentUserId() userId: number, @GetCurrentUser('refreshToken') refreshToken: string) {
        return this.authService.refreshTokens(userId, refreshToken);
    }

    @Get('google')
    @UseGuards(GoogleGuard)
    async googleLogin(@Req() req : Request) {}

    @Get('google/callback')
    @UseGuards(GoogleGuard)
    async googleLoginRedirect(@Req() req : Request, @Res() res: Response) {
        const token = await this.authService.oauthLogin(req);
        res.cookie('access_token', token.access_token, { sameSite : true, secure : true, httpOnly: true })
        return res.json(token);
    }

    @Get('github')
    @UseGuards(GithubGuard)
    async githubLogin(@Req() req : Request) {}

    @Get('github/callback')
    @UseGuards(GithubGuard)
    async githubLoginRedirect(@Req() req : Request, @Res() res : Response)  {
        const token = await this.authService.oauthLogin(req);
        res.cookie('access_token', token.access_token, { sameSite : true, secure : true, httpOnly: true })
        return res.json(token);
    }

}

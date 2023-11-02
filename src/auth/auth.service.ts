import {ForbiddenException, Injectable, Req} from '@nestjs/common';
import { PrismaService } from "../prisma/prisma.service";
import { RegisterAuthDto } from "./dto/register-auth.dto";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";
import { LoginAuthDto } from "./dto/login-auth.dto";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";
import * as argon from 'argon2';
import {GoogleAuthDto} from "./dto/google-auth.dto";

@Injectable()
export class AuthService {
    constructor(
        private prisma:PrismaService,
        private jwt:JwtService,
        private config:ConfigService,
    ) {}

    async register(dto : RegisterAuthDto) {
        let {username, email, password } = dto;
        const hashedPassword = await argon.hash(password);
        try {
            const user = await this.prisma.user.create({
                data: {
                    username,
                    email,
                    password : hashedPassword,
                }
            });
            delete user.password;
            return user;
        } catch (e) {
            if (e instanceof PrismaClientKnownRequestError && e.code === 'P2002') {
                throw new ForbiddenException('Username or email already exists');
            }
        throw e;
        }
    }

    async login(dto : LoginAuthDto) {
        const {email, password} = dto;
        const user = await this.prisma.user.findUnique({
            where: {
                email
            }
        });
        if (!user) {
            throw new ForbiddenException('Email not found!');
        }
        const isPasswordValid = await argon.verify(user.password, password);
        if (!isPasswordValid) {
            throw new ForbiddenException('Password is not valid!');
        }
        const payload = {
            sub: user.id,
            email: user.email,
        }
        return {
            access_token: await this.jwt.signAsync(payload, {
                secret:this.config.get('JWT_SECRET')
            }),
        };
    }

    // async googleLogin(dto : GoogleAuthDto) {
    //     const { email , picture, providerId, firstName, lastName } = dto;
    //     const tempUsername = "user" + Math.floor(Math.random() * 1000000);
    //     try {
    //         const user = await this.prisma.user.create({
    //             data: {
    //                 email : email,
    //                 profileImage: picture,
    //                 username: tempUsername,
    //                 firstName: firstName,
    //                 lastName: lastName,
    //                 providerId: providerId,
    //                 emailVerified: true,
    //                 provider: 'google',
    //             }
    //         });
    //         let payload = {
    //             sub: user.id,
    //             email: user.email,
    //         }
    //         return {
    //             access_token: await this.jwt.signAsync(payload, {
    //                 secret:this.config.get('JWT_SECRET')
    //             })
    //         }
    //     } catch (e) {
    //         if (e instanceof PrismaClientKnownRequestError && e.code === 'P2002') {
    //             const user = await this.prisma.user.findUnique({
    //                 where: {
    //                     email: email
    //                 }
    //             });
    //             let payload = {
    //                 sub: user.id,
    //                 email: user.email,
    //             }
    //             return {
    //                 access_token: await this.jwt.signAsync(payload, {
    //                     secret:this.config.get('JWT_SECRET')
    //                 })
    //             }
    //         }
    //     }
    //
    //
    // }

    async googleLogin(req) {
        return { user : req.user };
    }
    async githubLogin(req) {
        if (!req.user) {
            return 'No user from github';
        }
        return { user : req.user };
    }
}

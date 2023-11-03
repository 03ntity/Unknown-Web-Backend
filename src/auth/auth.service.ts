import {ForbiddenException, Injectable} from '@nestjs/common';
import {PrismaService} from "../prisma/prisma.service";
import {RegisterAuthDto} from "./dto/register-auth.dto";
import {PrismaClientKnownRequestError} from "@prisma/client/runtime/library";
import {LoginAuthDto} from "./dto/login-auth.dto";
import {JwtService} from "@nestjs/jwt";
import {ConfigService} from "@nestjs/config";
import * as argon from 'argon2';

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
            // const verifyToken = await this.hashData(password);
            const user = await this.prisma.user.create({
                data: {
                    username,
                    email,
                    // verifyToken,
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
        return await this.getTokens(user.id, user.email);
    }

    async oauthRegister(req : any) {
        const { username, email , providerId, provider, name, picture } = req.user;
        const usernameTemp = username ? username : "user" + Math.floor(Math.random() * 1000000);
        // const verifyToken = await this.hashData(email + providerId);
        try {
            await this.prisma.user.create({
                data: {
                    name,
                    username : usernameTemp,
                    email,
                    provider,
                    providerId,
                    // verifyToken,
                    profileImage: picture ? picture : null,
                }
            })
            const user = await this.prisma.user.findUnique({
                where: {
                    email : email,
                },
            })
            return await this.getTokens(user.id, user.email);
        } catch (e) {
            if (e instanceof PrismaClientKnownRequestError && e.code === 'P2002') {
                throw new ForbiddenException('Username or email already exists');
            }
            throw e;
        }
    }

    async oauthLogin(req : any) {
        const { email } = req.user;
        const user = await this.prisma.user.findUnique({
            where: {
                email
            }
        });
        if (!user) {
            return await this.oauthRegister(req);
        }
        return await this.getTokens(user.id, user.email);
    }

    async refreshTokens(id: number, refreshToken: string) {
        const user = await this.prisma.user.findUnique({
            where: {
                id : id,
            },
        });
        if (!user) throw new ForbiddenException('Access Denied');
        const accessToken = await this.jwt.signAsync({ sub : id, email : user.email }, {
            secret: this.config.get<string>('JWT_SECRET_TOKEN'),
            expiresIn: this.config.get<string>('JWT_SECRET_TOKEN_EXPIRED'),
        })
        return {
            access_token : accessToken,
        }
    }

    async getTokens(id : number, email : string) {
        const [accessToken, refreshToken ] = await Promise.all([
            this.jwt.signAsync({ sub : id, email }, {
                secret: this.config.get<string>('JWT_SECRET_TOKEN'),
                expiresIn : this.config.get<string>('JWT_SECRET_TOKEN_EXPIRED'),
            }),
            this.jwt.signAsync({ sub : id, email }, {
                secret: this.config.get<string>('JWT_REFRESH_TOKEN'),
                expiresIn :this.config.get<string>('JWT_REFRESH_TOKEN_EXPIRED')
            }),
        ]);
        return {
            access_token : accessToken,
            refresh_token : refreshToken,
        }
    }

}

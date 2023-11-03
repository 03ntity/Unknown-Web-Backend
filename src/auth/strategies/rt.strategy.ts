import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import {request, Request} from 'express';
import { ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtPayload, JwtPayloadWithRt } from '../types';

@Injectable()
export class RtStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
    constructor(config: ConfigService) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: config.get<string>('JWT_REFRESH_TOKEN'),
            passReqToCallback: true,
        });
    }

    async validate(req: Request, payload: JwtPayload): Promise<JwtPayloadWithRt> {
        const refreshToken = req?.get('Authorization')?.replace('Bearer', '').trim();
        if (!refreshToken) throw new ForbiddenException('Refresh token malformed');
        return {
            ...payload,
            refreshToken,
        };
    }
}
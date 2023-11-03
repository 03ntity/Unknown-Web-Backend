import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ConfigService } from "@nestjs/config";
import { Strategy, ExtractJwt } from "passport-jwt";
import { Request } from "express";
import { JwtPayload } from "../types";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
    constructor(config: ConfigService) {
        const extractJwtToken = (req : Request) => {
            let token = null;
            if (req && req.cookies) {
                token = req.cookies['access_token'];
            }
            return token || ExtractJwt.fromAuthHeaderAsBearerToken()(req);
        }
        super({
            jwtFromRequest: extractJwtToken,
            ignoreExpiration: false,
            secretOrKey: config.get<string>('JWT_SECRET_TOKEN'),
        });
    }

    async validate(payload : JwtPayload) {
        return {
            sub : payload.sub,
            email : payload.email,
        };
    }
}
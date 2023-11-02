import { PassportStrategy } from "@nestjs/passport";
import { Strategy } from "passport-github2";

export class GithubStrategy extends PassportStrategy(Strategy, 'github') {
    constructor() {
        super({
            clientID: '5573410e7033f538751c',
            clientSecret: 'f929ffde52f74be8cbfd37a9a99e7731371a1dff',
            callbackURL: 'http://localhost:3000/auth/github/callback',
            scope: ['user:email'],
        });
    }
    async validate(accessToken : string, refreshToken : string, profile : any, done) {
        const { id, username, emails } = profile;
        const user = {
            githubId: id,
            email: emails[0].value,
            username,
            accessToken,
        };
        done(null, user);
    }
}
import { PassportStrategy } from "@nestjs/passport";
import { Strategy } from "passport-github2";
import { ConfigService } from "@nestjs/config";

export class GithubStrategy extends PassportStrategy(Strategy, 'github') {
    constructor(config : ConfigService) {
        super({
            clientID: config.get<string>('GITHUB_CLIENT_ID'),
            clientSecret: config.get<string>('GITHUB_CLIENT_SECRET'),
            callbackURL: config.get<string>('GITHUB_CALLBACK_URL'),
            scope: ['user:email'],
        });
    }
    async validate(accessToken : string, refreshToken : string, profile : any, done) {
        const { id, username, emails, photos, provider, dipslayName } = profile;
        const user = {
            provider,
            providerId: id,
            email: emails[0].value,
            picture : photos[0].value,
            username,
            name: dipslayName,
            accessToken,
        };
        done(null, user);
    }
}
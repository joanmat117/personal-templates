import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { LoginDto } from './dto/login.dto';
import { JwtManagerService } from './jwt-manager.service';
import config from "src/common/config"
import * as crypto from "node:crypto";
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class AuthService {
  private readonly REFRESH_TOKEN_EXPIRES_IN: number = // date in seconds;

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtManager: JwtManagerService,
    private readonly prismaService:PrismaService
  ) {}

  async register(
    // register.dto
  ) {
    // provide user data
    return await this.usersService.create();
  }

  async validate(loginDto: LoginDto) {
    const { ...user } = await this.usersService.findBySome(loginDto.some);
    return user;
  }

  async login(loginDto: LoginDto) {
    const { id: userId } = await this.usersService.findBySome(loginDto.secretSome);
    const familyId = crypto.randomUUID();

    const accessToken = await this.jwtManager.generateAccessToken(userId);
    const refreshToken = await this.jwtManager.generateRefreshToken(userId, familyId);

    const tokenHash = this.jwtManager.hashToken(refreshToken);

    const expirationDate = new Date();
    expirationDate.setSeconds(
      expirationDate.getSeconds() +this.REFRESH_TOKEN_EXPIRES_IN
    );

    await this.prismaService.refresh_tokens.create({
      data: {
        token: tokenHash,
        user_id: userId,
        family_id: familyId,
        expires_at: expirationDate,
      }
    });

    return {
      accessToken,
      refreshToken
    };
  }

  async logout(refreshToken: string): Promise<void> {
    if (!refreshToken) return;

    const validation = await this.jwtManager.validateRefreshToken(refreshToken);

    if (validation.isValid && validation.tokenRecord) {

      await this.jwtManager.invalidateFamily(validation.tokenRecord.family_id);
    } 
  }

  async refreshTokens(refreshToken: string) {
    const validation = await this.jwtManager.validateRefreshToken(refreshToken);

    if (!validation.isValid || validation.isExpired || validation.isRevoked || validation.isUsed) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    await this.jwtManager.markTokenAsUsed(refreshToken);

    const { newAccessToken, newRefreshToken } = await this.jwtManager.rotateTokens(
      refreshToken,
      validation.payload!.sub,
      validation.payload!.familyId
    );

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken
    };
  }
}

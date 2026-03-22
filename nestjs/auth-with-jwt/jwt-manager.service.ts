import { Injectable, UnauthorizedException } from "@nestjs/common";
import { type Request,type Response } from "express";
import { ConfigService } from "@nestjs/config";
import {  JwtService, TokenExpiredError } from "@nestjs/jwt";
import { PrismaService } from "src/prisma/prisma.service";
import { AccessTokenPayload, RefreshTokenPayload } from "./types/jwt-tokens.types";
import * as crypto from "node:crypto";

@Injectable()
export class JwtManagerService {
  private readonly accessTokenCookieName: string = config.jwt.accessToken.cookieName;
  private readonly refreshTokenCookieName: string = config.jwt.refreshToken.cookieName;
  private readonly ACCESS_TOKEN_SECRET: string | undefined;
  private readonly REFRESH_TOKEN_SECRET: string | undefined;
  private readonly ACCESS_TOKEN_EXPIRES_IN: number = config.jwt.accessToken.expiresIn;
  private readonly REFRESH_TOKEN_EXPIRES_IN: number = config.jwt.refreshToken.expiresIn;

  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly prismaService: PrismaService
  ) {
    this.ACCESS_TOKEN_SECRET = this.configService.get("ACCESS_TOKEN_SECRET");
    this.REFRESH_TOKEN_SECRET = this.configService.get("REFRESH_TOKEN_SECRET");
  }

  getTokensFromCookies(req: Request): {
    accessToken: string | undefined;
    refreshToken: string | undefined;
  } {
    return {
      accessToken: req.cookies[this.accessTokenCookieName],
      refreshToken: req.cookies[this.refreshTokenCookieName],
    };
  }

  getTokensFromHeaders(req:Request): {
    accessToken:string|undefined;
    refreshToken:string|undefined;
  } {

    const accessToken = req.get(config.jwt.accessToken.headerName)

    const refreshToken = req.get(config.jwt.refreshToken.headerName)

    return {
      accessToken,
      refreshToken,
    }
  }

  async validateAccessToken(accessToken: string): Promise<{
    isValid: boolean;
    isExpired: boolean;
    payload: AccessTokenPayload | null;
  }> {
    try {
      const payload = await this.jwtService.verifyAsync<AccessTokenPayload>(accessToken, {
        secret: this.ACCESS_TOKEN_SECRET,
      });

      return {
        isValid: true,
        isExpired: false,
        payload,
      };
    } catch (e) {
      if (e instanceof TokenExpiredError) {
        return {
          isValid: false,
          isExpired: true,
          payload: null,
        };
      }
      
      return {
        isValid: false,
        isExpired: false,
        payload: null,
      };
    }
  }

  async validateRefreshToken(refreshToken: string): Promise<{
    isValid: boolean;
    isExpired: boolean;
    isRevoked: boolean;
    isUsed: boolean;
    payload: RefreshTokenPayload | null;
    tokenRecord?: any;
  }> {
    try {

      const payload = await this.jwtService.verifyAsync<RefreshTokenPayload>(refreshToken, {
        secret: this.REFRESH_TOKEN_SECRET
      });

      const tokenHash = this.hashToken(refreshToken)

      const tokenRecord = await this.prismaService.refresh_tokens.findUnique({
        where: { token: tokenHash },
        include: { user: true }
      });

      if (!tokenRecord) {
        return {
          isValid: false,
          isExpired: false,
          isRevoked: false,
          isUsed: false,
          payload: null,
        };
      }

      return {
        isValid: true,
        isExpired: tokenRecord.expired || new Date() > tokenRecord.expires_at,
        isRevoked: tokenRecord.revoked,
        isUsed: tokenRecord.used,
        payload,
        tokenRecord
      };

    } catch (e) {
      if (e instanceof TokenExpiredError) {
        return {
          isValid: false,
          isExpired: true,
          isRevoked: false,
          isUsed: false,
          payload: null,
        };
      }
      
      return {
        isValid: false,
        isExpired: false,
        isRevoked: false,
        isUsed: false,
        payload: null,
      };
    }
  }

  async invalidateFamily(familyId: string): Promise<void> {
    await this.prismaService.refresh_tokens.updateMany({
      where: { family_id: familyId },
      data: { revoked: true }
    });
  }

  async rotateTokens(oldRefreshToken: string, userId: string, familyId: string): Promise<{
  newAccessToken: string;
  newRefreshToken: string;
}> {

  const oldTokenHash = this.hashToken(oldRefreshToken);

  const existingToken = await this.prismaService.refresh_tokens.findFirst({
    where: { 
      token: oldTokenHash,
      family_id: familyId,
      user_id: userId
    }
  });

  if (!existingToken) {
    throw new UnauthorizedException('Invalid token');
  }

  const newAccessToken = await this.generateAccessToken(userId);
  const newRefreshToken = await this.generateRefreshToken(userId, familyId);

  const newTokenHash = this.hashToken(newRefreshToken);

  const expirationDate = new Date();
  expirationDate.setSeconds(expirationDate.getSeconds() + this.REFRESH_TOKEN_EXPIRES_IN);

  await this.prismaService.refresh_tokens.create({
    data: {
      token: newTokenHash,
      user_id: userId,
      family_id: familyId,
      expires_at: expirationDate,
    }
  });

  return {
    newAccessToken,
    newRefreshToken
  };
}
  async markTokenAsUsed(token: string): Promise<void> {
    const tokenHash = this.hashToken(token) 

    await this.prismaService.refresh_tokens.update({
      where: { token: tokenHash },
      data: { used: true }
    });
  }

  async generateAccessToken(userId: string): Promise<string> {
    return this.jwtService.signAsync<AccessTokenPayload>(
      { sub: userId },
      {
        expiresIn: this.ACCESS_TOKEN_EXPIRES_IN,
        secret: this.ACCESS_TOKEN_SECRET
      }
    );
  }

  async generateRefreshToken(userId: string, familyId: string): Promise<string> {
    return this.jwtService.signAsync<RefreshTokenPayload>(
      { sub: userId, familyId, version: 1 },
      {
        expiresIn: this.REFRESH_TOKEN_EXPIRES_IN,
        secret: this.REFRESH_TOKEN_SECRET
      }
    );
  }

  setTokensInCookies(res: Response, accessToken: string, refreshToken: string): void {
    const isProduction = process.env.NODE_ENV === 'production';
    
    res.cookie(this.accessTokenCookieName, accessToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      maxAge: this.ACCESS_TOKEN_EXPIRES_IN * 1000
    });

    res.cookie(this.refreshTokenCookieName, refreshToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      maxAge: this.REFRESH_TOKEN_EXPIRES_IN * 1000
    });
  }

  clearTokensFromCookies(res: any): void {
    res.clearCookie(this.accessTokenCookieName);
    res.clearCookie(this.refreshTokenCookieName);
  }

  hashToken(token:string){
    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");
  }
}

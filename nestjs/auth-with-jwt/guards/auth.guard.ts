import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { type Request, type Response } from "express";
import { JwtManagerService } from "../jwt-manager.service";

@Injectable()
export class AuthGuard implements CanActivate {
  
  constructor(
    private readonly jwtManager: JwtManagerService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const ctx = context.switchToHttp();
    const req = ctx.getRequest<Request>();
    const res = ctx.getResponse<Response>();

    const { accessToken, refreshToken } = this.jwtManager.getTokensFromCookies(req);

    if(!accessToken) throw new UnauthorizedException("Access token not found")

    const accessValidation = await this.jwtManager.validateAccessToken(accessToken);
    
    if (accessValidation.isValid && accessValidation.payload) {
      req["user"] = accessValidation.payload;
      return true;
    }

    if (!accessValidation.isExpired) {
      throw new UnauthorizedException("Invalid access token");
    }

    if (!refreshToken) {
      this.jwtManager.clearTokensFromCookies(res);
      throw new UnauthorizedException("No refresh token provided");
    } 

    const refreshValidation = await this.jwtManager.validateRefreshToken(refreshToken);

    if (refreshValidation.isUsed) {
      if (refreshValidation.tokenRecord) {
        await this.jwtManager.invalidateFamily(refreshValidation.tokenRecord.family_id);
      }
      this.jwtManager.clearTokensFromCookies(res);
      throw new UnauthorizedException("Refresh token has been used - possible theft");
    }

    if (refreshValidation.isRevoked) {
      this.jwtManager.clearTokensFromCookies(res);
      throw new UnauthorizedException("Refresh token revoked");
    }

    if (refreshValidation.isExpired) {
      this.jwtManager.clearTokensFromCookies(res);
      throw new UnauthorizedException("Refresh token expired");
    }

    if (refreshValidation.isValid && refreshValidation.payload && refreshValidation.tokenRecord) {
      
      await this.jwtManager.markTokenAsUsed(refreshToken);

      const { newAccessToken, newRefreshToken } = await this.jwtManager.rotateTokens(
        refreshToken,
        refreshValidation.payload.sub,
        refreshValidation.payload.familyId
      );

      this.jwtManager.setTokensInCookies(res, newAccessToken, newRefreshToken);
      req["user"] = { sub: refreshValidation.payload.sub };

      return true;
    }

    this.jwtManager.clearTokensFromCookies(res);
    throw new UnauthorizedException("Invalid authentication");
  }
}

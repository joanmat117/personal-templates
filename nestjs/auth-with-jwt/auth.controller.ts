import { Body, Controller, HttpCode, HttpStatus, Post, Res, Req, UseGuards, UnauthorizedException} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { type Response, type Request } from 'express';
import { JwtManagerService } from './jwt-manager.service';
import { AuthGuard } from './guards/auth.guard';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly jwtManager: JwtManagerService
  ) {}

  @Post("register")
  @HttpCode(HttpStatus.CREATED)
  async register(
    //register.dto
  ) {
    const newUser = await this.authService.register(
      //register.dto
    );

    return {
      message: "Register successful",
      data: {
        // user data
      }
    };
  }

  @Post("login")
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) res: Response
  ) {

    const { accessToken, refreshToken } = await this.authService.login(loginDto);

    this.jwtManager.setTokensInCookies(res, accessToken, refreshToken);

    return {
      message: "Login successful",
    };
  }

  @Post("logout")
  @HttpCode(HttpStatus.OK)
  @UseGuards(AuthGuard)
  async logout(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ) {
    const { refreshToken } = this.jwtManager.getTokensFromCookies(req);

    if (refreshToken) {
      await this.authService.logout(refreshToken);
    }

    this.jwtManager.clearTokensFromCookies(res);

    return {
      message: "Logout successful"
    };
  }

  //Useful if tokens are not stored in cookies
  @Post("refresh")
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ) {
    const { refreshToken } = this.jwtManager.getTokensFromCookies(req);

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token not found');
    }

    const { accessToken, refreshToken: newRefreshToken } = 
      await this.authService.refreshTokens(refreshToken);

    this.jwtManager.setTokensInCookies(res, accessToken, newRefreshToken);

    return {
      message: "Tokens refreshed successfully",
      accessToken,
      refreshToken: newRefreshToken
    };
  }
}

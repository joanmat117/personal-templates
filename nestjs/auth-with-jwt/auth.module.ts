import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from 'src/users/users.module';
import { JwtModule } from '@nestjs/jwt';
import { JwtManagerService } from './jwt-manager.service';
import { AuthGuard } from './guards/auth.guard';

@Module({
  controllers: [AuthController],
  providers: [AuthGuard,JwtManagerService,AuthService],
  exports: [AuthGuard,JwtManagerService],
  imports:[
    UsersModule,
    JwtModule.register({
      global:true,
    })
  ]
})
export class AuthModule {}

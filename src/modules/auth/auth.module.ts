import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './jwt.strategy';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '../users/entities/user.entity';

@Module({
  imports:[
    JwtModule.register({
      secret: "Mi_codigo_secreto", 
      signOptions:{expiresIn:'60m'}
    }),
    TypeOrmModule.forFeature([User])
  ],
  providers: [AuthService,JwtStrategy],
  controllers: [AuthController]
})
export class AuthModule {}

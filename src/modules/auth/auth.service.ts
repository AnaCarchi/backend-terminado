import { HttpException, Injectable } from '@nestjs/common';
//import { LoginAuthDto } from './dto/login-auth.dto';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from '../users/entities/user.entity';
import { Repository } from 'typeorm';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { hash,compare } from 'bcrypt';
import { LoginAuthDto } from './dto/login-auth.dto';

@Injectable()
export class AuthService {

    constructor(private jwtservice:JwtService,
            @InjectRepository(User) private userRepository: Repository<User>){}

    async funRegister(objUser: RegisterAuthDto){
        const {password}=objUser //capturamos solo password de todo el objeto
        //console.log("Antes: ",objUser)
        const plainToHash=await hash(password, 12) 
        //console.log(plainToHash) 
        
        objUser={...objUser, password:plainToHash}
        
        console.log("Despues: ", objUser)

        return this.userRepository.save(objUser); 
    }
    async login(credenciales:LoginAuthDto){
        
        const {email,password}=credenciales
        const user=await this.userRepository.findOne({
            where:{
                email: email
            }
        });

        if(!user) return new HttpException('Usuario no encontrado',404);
        
        const verificarPass = await compare(password, user.password)//compare lo importamis manualemente
        
        if(!verificarPass) throw new HttpException('Password invalido',401)

        let payload={email:user.email, id:user.id}
        const token= this.jwtservice.sign(payload)
        return {user:user,token:token};
    }
}


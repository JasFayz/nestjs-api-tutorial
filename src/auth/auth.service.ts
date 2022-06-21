import {
  ForbiddenException,
  Injectable,
  NotFoundException,
  Req,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDTO } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Injectable()
export class AuthService {
  constructor(private prismaSrvice: PrismaService) {}

  async signup(dto: AuthDTO) {
    //generate password
    const hash = await argon.hash(dto.password);

    //save new user
    try {
      const user = await this.prismaSrvice.user.create({
        data: {
          email: dto.email,
          hash,
        },
        select: {
          id: true,
          email: true,
          createdAt: true,
        },
      });
      // return the saved user
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }

      throw error;
    }
  }

  async signin(dto: AuthDTO) {
    //find the user by email
    const user = await this.prismaSrvice.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    //if user does not exist throw exception
    if (!user) throw new ForbiddenException('Credentials incorect');
    //compare password
    const pwMatches = await argon.verify(user.hash, dto.password);
    //if password incorect throw exception
    if (pwMatches) throw new ForbiddenException('Credentials incorect');
    //send back the user
    delete user.hash;
    return user;
  }
}

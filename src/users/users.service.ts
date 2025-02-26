import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './entities/user.entity';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async findAll(): Promise<User[]> {
    const users = await this.prisma.user.findMany();
    if (!users) throw new NotFoundException('Users not found');
    return users;
  }

  async findByEmail(email: string): Promise<User> {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  async findByUsername(username: string): Promise<User> {
    const user = await this.prisma.user.findUnique({ where: { username } });
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  async findOne(id: string): Promise<User> {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  async create(data: CreateUserDto): Promise<User> {
    const user = await this.prisma.user.create({ data });
    if (!user) throw new NotFoundException('User not created');
    return user;
  }

  async update(id: string, data: UpdateUserDto): Promise<User> {
    const user = await this.prisma.user.update({ where: { id }, data });
    if (!user) throw new NotFoundException('User not updated');
    return user;
  }

  async remove(id: string): Promise<User> {
    const user = await this.prisma.user.delete({ where: { id } });
    if (!user) throw new NotFoundException('User not deleted');
    return user;
  }
}

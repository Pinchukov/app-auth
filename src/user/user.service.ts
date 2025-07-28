import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { Role, User, News } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import * as argon2 from 'argon2';

// Тип, описывающий пользователя без пароля и refreshToken, но с массивом новостей
type UserWithNews = Omit<User, 'password' | 'refreshToken'> & { news: News[] };

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) { }

  async create(createUserDto: CreateUserDto): Promise<User> {
    const { email, password, name, role = Role.USER } = createUserDto;

    // Защита: если пытаются создать пользователя с ролью ADMIN, сбрасываем её на USER
    // Чтобы нельзя было напрямую через create создать админа
    const assignedRole = role === Role.ADMIN ? Role.USER : role;

    // Проверка на дублирование email
    const existingUser = await this.prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      throw new ConflictException('Пользователь с таким email уже существует');
    }

    // Хешируем пароль с помощью argon2 для безопасности
    const hashedPassword = await argon2.hash(password);

    // Создаем пользователя в базе с безопасным паролем и назначенной ролью
    return this.prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
        role: assignedRole,
        // Если в DTO передан статус — используем его, иначе по умолчанию false
        status: createUserDto.status ?? false,
      },
    });
  }

  findAll(): Promise<UserWithNews[]> {
    return this.prisma.user.findMany({
      where: { status: true }, // только активные пользователи
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        status: true,
        createdAt: true,
        updatedAt: true,
        news: true, // включаем связанные новости
      },
    });
  }

  async findById(id: number): Promise<User> {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }
    return user;
  }

  async findOne(id: number): Promise<UserWithNews> {
    const user = await this.prisma.user.findUnique({
      where: { id },
      include: {
        news: true,
      },
    });
    if (!user) {
      throw new NotFoundException(`Пользователь с ID ${id} не найден`);
    }
    return user;
  }

  async update(id: number, updateUserDto: UpdateUserDto): Promise<User> {
    const { email, password, role, status, name } = updateUserDto;

    // Проверяем, существует ли пользователь
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) {
      throw new NotFoundException(`Пользователь с ID ${id} не найден`);
    }

    // Если пытаемся изменить email — убеждаемся, что новый email не занят другим пользователем
    if (email && email !== user.email) {
      const existingUser = await this.prisma.user.findUnique({ where: { email } });
      if (existingUser) {
        throw new ConflictException('Пользователь с таким email уже существует');
      }
    }

    // Если передан новый пароль — хешируем его, иначе оставляем старый
    let hashedPassword = user.password;
    if (password) {
      hashedPassword = await argon2.hash(password);
    }

    // Обновляем пользователя с переданными данными (undefined поля не будут обновляться)
    return this.prisma.user.update({
      where: { id },
      data: {
        name: name ?? undefined,
        email: email ?? undefined,
        password: hashedPassword,
        role: role ?? undefined,
        status: status ?? undefined,
      },
    });
  }

  async remove(id: number): Promise<User> {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) {
      throw new NotFoundException(`Пользователь с ID ${id} не найден`);
    }
    return this.prisma.user.delete({ where: { id } });
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.prisma.user.findUnique({ where: { email } });
  }
}

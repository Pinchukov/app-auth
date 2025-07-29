import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { Role, User, News } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import * as argon2 from 'argon2';
import { Prisma } from '@prisma/client';

// Тип пользователя без пароля и refreshToken, но с новостями
type UserWithNews = Omit<User, 'password' | 'refreshToken'> & { news: News[] };

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  // Приватный метод для обработки ошибки уникального ограничения по email
  private handleUniqueEmailError(error: unknown): void {
    if (
      error instanceof Prisma.PrismaClientKnownRequestError &&
      error.code === 'P2002' &&
      (
        (typeof error.meta?.target === 'string' && error.meta.target.includes('email')) ||
        (Array.isArray(error.meta?.target) && error.meta.target.includes('email'))
      )
    ) {
      throw new ConflictException('Пользователь с таким email уже существует');
    }
  }

  // Приватный метод для проверки существования пользователя по id
  private async ensureUserExists(id: number) {
    const existing = await this.prisma.user.findUnique({ where: { id } });
    if (!existing) {
      throw new NotFoundException(`Пользователь с ID ${id} не найден`);
    }
  }

  // Создание нового пользователя с хешированием пароля и обработкой ошибок
  async create(createUserDto: CreateUserDto): Promise<User> {
    const { email, password, role = Role.USER, ...rest } = createUserDto;

    // Защита: не даём создавать админа напрямую
    const assignedRole = role === Role.ADMIN ? Role.USER : role;

    const hashedPassword = await argon2.hash(password);

    try {
      return await this.prisma.user.create({
        data: {
          email,
          password: hashedPassword,
          role: assignedRole,
          status: createUserDto.status ?? false,
          ...rest,
        },
      });
    } catch (error) {
      this.handleUniqueEmailError(error);
      throw error;
    }
  }

  // Получить всех активных пользователей с их новостями, без паролей и токенов
  findAll(): Promise<UserWithNews[]> {
    return this.prisma.user.findMany({
      where: { status: true },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        status: true,
        createdAt: true,
        updatedAt: true,
        news: true,
      },
    });
  }

  // Получить пользователя по ID (полный объект)
  async findById(id: number): Promise<User> {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) {
      throw new NotFoundException(`Пользователь с ID ${id} не найден`);
    }
    return user;
  }

  // Получить пользователя с новостями по ID
  async findOne(id: number): Promise<UserWithNews> {
    const user = await this.prisma.user.findUnique({
      where: { id },
      include: { news: true },
    });
    if (!user) {
      throw new NotFoundException(`Пользователь с ID ${id} не найден`);
    }
    return user;
  }

  // Обновление пользователя с проверкой уникальности email и хешированием пароля
  async update(id: number, updateUserDto: UpdateUserDto): Promise<User> {
    await this.ensureUserExists(id);

    const { email, password, ...rest } = updateUserDto;

    let hashedPassword: string | undefined;

    if (password) {
      hashedPassword = await argon2.hash(password);
    }

    try {
      return await this.prisma.user.update({
        where: { id },
        data: {
          email: email ?? undefined,
          password: hashedPassword ?? undefined,
          ...rest,
        },
      });
    } catch (error) {
      this.handleUniqueEmailError(error);
      throw error;
    }
  }

  // Удаление пользователя по ID
  async remove(id: number): Promise<User> {
    await this.ensureUserExists(id);
    return this.prisma.user.delete({ where: { id } });
  }

  // Поиск пользователя по email
  async findByEmail(email: string): Promise<User | null> {
    return this.prisma.user.findUnique({ where: { email } });
  }
}

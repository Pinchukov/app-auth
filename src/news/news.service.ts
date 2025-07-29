import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { plainToInstance } from 'class-transformer';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateNewsDto } from './dto/create-news.dto';
import { UpdateNewsDto } from './dto/update-news.dto';
import { UserDto } from 'src/user/dto/user.dto';
import { Prisma } from '@prisma/client';

@Injectable()
export class NewsService {
  constructor(private prisma: PrismaService) {}

  // Проверка ошибки уникального ограничения по URL
  private handleUniqueUrlError(error: unknown): void {
    if (
      error instanceof Prisma.PrismaClientKnownRequestError &&
      error.code === 'P2002' &&
      (
        (typeof error.meta?.target === 'string' && error.meta.target.includes('url')) ||
        (Array.isArray(error.meta?.target) && error.meta.target.includes('url'))
      )
    ) {
      throw new BadRequestException('Новость с таким URL уже существует');
    }
  }

  // Проверка существования новости по ID
  private async ensureNewsExists(id: number) {
    const existing = await this.prisma.news.findUnique({ where: { id } });
    if (!existing) {
      throw new NotFoundException(`Новость с id ${id} не найдена`);
    }
  }

  // Создание новости с обработкой ошибки уникального URL
  async create(createNewsDto: CreateNewsDto) {
    try {
      return await this.prisma.news.create({ data: { ...createNewsDto } });
    } catch (error) {
      this.handleUniqueUrlError(error);
      throw error;
    }
  }

  // Получить все активные новости с автором в виде UserDto
  async findAll() {
    const news = await this.prisma.news.findMany({
      where: { status: true },
      include: { author: true },
    });
    news.forEach(newsItem => {
      newsItem.author = plainToInstance(UserDto, newsItem.author, { excludeExtraneousValues: true });
    });
    return news;
  }

  // Получить новость по ID
  async findOne(id: number) {
    const news = await this.prisma.news.findUnique({
      where: { id },
      include: { author: true },
    });
    if (!news) {
      throw new NotFoundException(`Новость с id ${id} не найдена`);
    }
    return news;
  }

  // Получить новость по URL
  async findByUrl(url: string) {
    const news = await this.prisma.news.findUnique({
      where: { url },
      include: { author: true },
    });
    if (!news) {
      throw new NotFoundException(`Новость с url "${url}" не найдена`);
    }
    return news;
  }

  // Обновить новость с обработкой ошибки уникального URL
  async update(id: number, updateNewsDto: UpdateNewsDto) {
    await this.ensureNewsExists(id);
    try {
      return await this.prisma.news.update({
        where: { id },
        data: { ...updateNewsDto },
      });
    } catch (error) {
      this.handleUniqueUrlError(error);
      throw error;
    }
  }

  // Удалить новость по ID
  async remove(id: number): Promise<void> {
    await this.ensureNewsExists(id);
    await this.prisma.news.delete({ where: { id } });
  }
}

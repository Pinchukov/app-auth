import { Injectable, NotFoundException } from '@nestjs/common';
import { plainToInstance } from 'class-transformer';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateNewsDto } from './dto/create-news.dto';
import { UpdateNewsDto } from './dto/update-news.dto';
import { UserDto } from 'src/user/dto/user.dto';

@Injectable()
export class NewsService {
  constructor(private prisma: PrismaService) {}

  async create(createNewsDto: CreateNewsDto) {
    return this.prisma.news.create({
      data: {
        ...createNewsDto,
      },
    });
  }

  async findAll() {
    const news = await this.prisma.news.findMany({
      where: { status: true },
      include: { author: true },
    });

    // Преобразуем каждого автора к UserDto, скрывая чувствительные поля
    news.forEach(newsItem => {
      newsItem.author = plainToInstance(UserDto, newsItem.author, { excludeExtraneousValues: true });
    });

    return news;
  }

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

  async update(id: number, updateNewsDto: UpdateNewsDto) {
    const existing = await this.prisma.news.findUnique({ where: { id } });
    if (!existing) {
      throw new NotFoundException(`Новость с id ${id} не найдена`);
    }

    return this.prisma.news.update({
      where: { id },
      data: {
        ...updateNewsDto,
        // предполагается, что Prisma обновит updatedAt автоматически
      },
    });
  }

  async remove(id: number): Promise<void> {
    const existing = await this.prisma.news.findUnique({ where: { id } });
    if (!existing) {
      throw new NotFoundException(`Новость с id ${id} не найдена`);
    }

    await this.prisma.news.delete({ where: { id } });
  }
}

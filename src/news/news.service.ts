import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { plainToInstance } from 'class-transformer';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateNewsDto } from './dto/create-news.dto';
import { UpdateNewsDto } from './dto/update-news.dto';
import { Prisma, Role } from '@prisma/client';
import { NewsWithAuthor } from './dto/news-with-author.interface';
import { AuthorUserDto } from './dto/author-user.dto';
import { AuthorAdminDto } from './dto/author-admin.dto';

@Injectable()
export class NewsService {
  private static readonly UNIQUE_CONSTRAINT_ERROR_CODE = 'P2002';
  private static readonly URL_CONSTRAINT_FIELD = 'url';
  private static readonly ERROR_MESSAGES = {
    DUPLICATE_URL: 'Новость с таким URL уже существует',
    NEWS_NOT_FOUND_BY_ID: (id: number) => `Новость с id ${id} не найдена`,
    NEWS_NOT_FOUND_BY_URL: (url: string) => `Новость с url "${url}" не найдена`,
  };

  constructor(private readonly prisma: PrismaService) {}

  async create(createNewsDto: CreateNewsDto) {
    try {
      return await this.prisma.news.create({ 
        data: createNewsDto 
      });
    } catch (error) {
      this.handleUniqueUrlError(error);
      throw error;
    }
  }

  async findAll(userRole: Role): Promise<NewsWithAuthor[]> {
    const news = await this.getActiveNewsWithAuthors();
    
    return news.map(newsItem => this.mapNewsToWithAuthor(newsItem, userRole));
  }

  async findOne(id: number, userRole: Role): Promise<NewsWithAuthor> {
    const news = await this.getNewsWithAuthorById(id);

    if (!news) {
      throw new NotFoundException(NewsService.ERROR_MESSAGES.NEWS_NOT_FOUND_BY_ID(id));
    }

    return this.mapNewsToWithAuthor(news, userRole);
  }

  async findByUrl(url: string, userRole: Role): Promise<NewsWithAuthor> {
    const news = await this.getNewsWithAuthorByUrl(url);

    if (!news) {
      throw new NotFoundException(NewsService.ERROR_MESSAGES.NEWS_NOT_FOUND_BY_URL(url));
    }

    return this.mapNewsToWithAuthor(news, userRole);
  }

  async update(id: number, updateNewsDto: UpdateNewsDto) {
    await this.ensureNewsExists(id);

    try {
      return await this.prisma.news.update({
        where: { id },
        data: updateNewsDto,
      });
    } catch (error) {
      this.handleUniqueUrlError(error);
      throw error;
    }
  }

  async remove(id: number): Promise<void> {
    await this.ensureNewsExists(id);
    await this.prisma.news.delete({ where: { id } });
  }

  // Методы для трансформации данных
  private mapNewsToWithAuthor(newsItem: any, userRole: Role): NewsWithAuthor {
    return {
      id: newsItem.id,
      title: newsItem.title,
      text: newsItem.text,
      url: newsItem.url,
      status: newsItem.status,
      createdAt: newsItem.createdAt,
      updatedAt: newsItem.updatedAt,
      authorId: newsItem.authorId,
      author: this.transformAuthor(newsItem.author, userRole),
    };
  }

  private transformAuthor(author: any, userRole: Role): AuthorUserDto | AuthorAdminDto {
    const AuthorDtoClass = userRole === Role.ADMIN ? AuthorAdminDto : AuthorUserDto;
    
    return plainToInstance(AuthorDtoClass, author, { 
      excludeExtraneousValues: true 
    });
  }

  // Приватные методы для работы с данными
  private async getActiveNewsWithAuthors() {
    return this.prisma.news.findMany({
      where: { status: true },
      include: { author: true },
    });
  }

  private async getNewsWithAuthorById(id: number) {
    return this.prisma.news.findUnique({
      where: { id },
      include: { author: true },
    });
  }

  private async getNewsWithAuthorByUrl(url: string) {
    return this.prisma.news.findUnique({
      where: { url },
      include: { author: true },
    });
  }

  private async ensureNewsExists(id: number): Promise<void> {
    const existing = await this.prisma.news.findUnique({ 
      where: { id },
      select: { id: true } // Выбираем только id для оптимизации
    });
    
    if (!existing) {
      throw new NotFoundException(NewsService.ERROR_MESSAGES.NEWS_NOT_FOUND_BY_ID(id));
    }
  }

  // Методы для обработки ошибок
  private handleUniqueUrlError(error: unknown): void {
    if (!this.isUniqueUrlConstraintError(error)) {
      return;
    }

    throw new BadRequestException(NewsService.ERROR_MESSAGES.DUPLICATE_URL);
  }

  private isUniqueUrlConstraintError(error: unknown): boolean {
    if (!(error instanceof Prisma.PrismaClientKnownRequestError)) {
      return false;
    }

    if (error.code !== NewsService.UNIQUE_CONSTRAINT_ERROR_CODE) {
      return false;
    }

    const target = error.meta?.target;
    
    if (typeof target === 'string') {
      return target.includes(NewsService.URL_CONSTRAINT_FIELD);
    }
    
    if (Array.isArray(target)) {
      return target.includes(NewsService.URL_CONSTRAINT_FIELD);
    }

    return false;
  }
}
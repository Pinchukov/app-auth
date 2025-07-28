import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  ParseIntPipe,
  UseGuards,
  HttpCode,
} from '@nestjs/common';

import { NewsService } from './news.service';
import { CreateNewsDto } from './dto/create-news.dto';
import { UpdateNewsDto } from './dto/update-news.dto';

import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/guards/roles.decorator';
import { Role } from '@prisma/client';

@Controller('news')
@UseGuards(JwtAuthGuard, RolesGuard)
export class NewsController {
  constructor(private readonly newsService: NewsService) {}

  @Post('create')
  @Roles(Role.ADMIN)
  @HttpCode(201)
  create(@Body() createNewsDto: CreateNewsDto) {
    return this.newsService.create(createNewsDto);
  }

  @Get('all')
  @Roles(Role.ADMIN, Role.USER)
  @HttpCode(200)
  findAll() {
    return this.newsService.findAll();
  }

  @Get(':id')
  @Roles(Role.ADMIN, Role.USER)
  @HttpCode(200)
  findOne(@Param('id', ParseIntPipe) id: number) {
    return this.newsService.findOne(id);
  }

  @Get('url/:url')
  @Roles(Role.ADMIN, Role.USER)
  @HttpCode(200)
  findByUrl(@Param('url') url: string) {
    return this.newsService.findByUrl(url);
  }

  @Patch(':id')
  @Roles(Role.ADMIN)
  @HttpCode(200)
  update(
    @Param('id', ParseIntPipe) id: number,
    @Body() updateNewsDto: UpdateNewsDto,
  ) {
    return this.newsService.update(id, updateNewsDto);
  }

  @Delete(':id')
  @Roles(Role.ADMIN)
  @HttpCode(204)
  remove(@Param('id', ParseIntPipe) id: number) {
    return this.newsService.remove(id);
  }
}

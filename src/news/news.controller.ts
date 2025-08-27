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
  Request,
} from '@nestjs/common';

import { Request as ExpressRequest } from 'express';

import { NewsService } from './news.service';
import { CreateNewsDto } from './dto/create-news.dto';
import { UpdateNewsDto } from './dto/update-news.dto';

import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/guards/roles.decorator';
import { Role } from '@prisma/client';
import { Public } from '../auth/decorators/public.decorator';

interface IUserRequest extends ExpressRequest {
  user: {
    role: Role;
    // Можно добавить другие поля, если нужно: id, email и т.д.
  };
}

@Controller('news')
@UseGuards(JwtAuthGuard, RolesGuard)
export class NewsController {
  constructor(private readonly newsService: NewsService) { }

  @Post('create')
  @Roles(Role.ADMIN)
  @HttpCode(201)
  create(@Body() createNewsDto: CreateNewsDto) {
    return this.newsService.create(createNewsDto);
  }

  // @Get('all')
  // //@Roles(Role.ADMIN, Role.USER)
  // @HttpCode(200)
  // findAll(@Request() req: IUserRequest) {
  //   const userRole = req.user.role;
  //   return this.newsService.findAll(userRole);
  // }

  @Get('all')
  @Public()
  @HttpCode(200)
  findAll(@Request() req: IUserRequest) {
    const userRole = req.user?.role ?? null;
    return this.newsService.findAll(userRole);
  }


  @Get(':id')
  @Roles(Role.ADMIN, Role.USER)
  @HttpCode(200)
  findOne(@Param('id', ParseIntPipe) id: number, @Request() req: IUserRequest) {
    const userRole = req.user.role;
    return this.newsService.findOne(id, userRole);
  }

  @Get('url/:url')
  @Roles(Role.ADMIN, Role.USER)
  @HttpCode(200)
  findByUrl(@Param('url') url: string, @Request() req: IUserRequest) {
    const userRole = req.user.role;
    return this.newsService.findByUrl(url, userRole);
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

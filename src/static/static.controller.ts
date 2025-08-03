import { Controller, Get, Res, NotFoundException, Logger } from '@nestjs/common';
import { Response } from 'express';
import { join } from 'path';
import { existsSync } from 'fs';

@Controller()
export class StaticController {
  private readonly logger = new Logger(StaticController.name);

  @Get('favicon.ico')
  async getFavicon(@Res() res: Response) {
    return this.sendFile('favicon.ico', res);
  }

  @Get('logo_120.png')
  async getLogo(@Res() res: Response) {
    return this.sendFile('logo_120.png', res);
  }

  private sendFile(filename: string, res: Response) {
    // В development режиме файлы в папке public/
    // В production режиме файлы в папке dist/public/
    const isProduction = process.env.NODE_ENV === 'production';
    const publicPath = isProduction 
      ? join(process.cwd(), 'dist', 'public')
      : join(process.cwd(), 'public');
    
    const filePath = join(publicPath, filename);
    
    this.logger.log(`Trying to serve file: ${filePath}`);
    this.logger.log(`File exists: ${existsSync(filePath)}`);
    
    if (!existsSync(filePath)) {
      this.logger.error(`File not found: ${filePath}`);
      throw new NotFoundException(`File ${filename} not found`);
    }

    // Устанавливаем правильный Content-Type
    if (filename.endsWith('.png')) {
      res.setHeader('Content-Type', 'image/png');
    } else if (filename.endsWith('.ico')) {
      res.setHeader('Content-Type', 'image/x-icon');
    }

    this.logger.log(`Successfully serving file: ${filename}`);
    return res.sendFile(filePath);
  }
}
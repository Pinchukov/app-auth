import { Module } from '@nestjs/common';                                                        
import { ConfigModule } from '@nestjs/config';                 
import { AppController } from './app.controller';              
import { AppService } from './app.service';                    
import { PrismaModule } from './prisma/prisma.module';         
import { PrismaService } from './prisma/prisma.service';
import { SecurityModule } from './security/security.module';   
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { NewsModule } from './news/news.module';
import { StaticController } from './static/static.controller';

// Определяем среду выполнения
const environment = process.env.NODE_ENV || 'development';

@Module({
  imports: [
    // Загрузка переменных окружения только для development и production
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: [
        `.env.${environment}`,        // .env.development или .env.production
      ],
      expandVariables: true,
      // Здесь можно добавить validationSchema для валидации env переменных
    }),
    PrismaModule,     
    AuthModule,       
    SecurityModule,   
    UserModule,
    NewsModule
  ],
  controllers: [AppController, StaticController],
  providers: [AppService, PrismaService],
})
export class AppModule { }
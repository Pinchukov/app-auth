import { PrismaClient, Role } from '@prisma/client';
import * as argon2 from 'argon2';

const prisma = new PrismaClient();

async function main() {
  // Хеширование пароля для пользователя с ролью ADMIN
  const adminPasswordHash = await argon2.hash('passwordMrPin123');

  const adminUser = await prisma.user.create({
    data: {
      name: 'mr.Pin',
      email: 'mr-pin@example.com',
      password: adminPasswordHash,
      role: Role.ADMIN,
      status: true,
    },
  });

  // Хеширование паролей для пользователей USER
  const user1PasswordHash = await argon2.hash('passwordAlice123');
  const user2PasswordHash = await argon2.hash('passwordBob123');

  const user1 = await prisma.user.create({
    data: {
      name: 'Alice',
      email: 'alice@example.com',
      password: user1PasswordHash,
      role: Role.USER,
      status: true,
    },
  });

  const user2 = await prisma.user.create({
    data: {
      name: 'Bob',
      email: 'bob@example.com',
      password: user2PasswordHash,
      role: Role.USER,
      status: true,
    },
  });

  // Создаем новости, связывая с пользователями
  await prisma.news.createMany({
    data: [
      {
        title: 'Первый пост от admin',
        text: 'Это тестовая новость номер один, созданная администратором.',
        url: 'first-post-admin',
        status: true,
        authorId: adminUser.id,
      },
      {
        title: 'Вторая новость от Alice',
        text: 'Новости от пользователя Alice, проверка работы.',
        url: 'news-from-alice',
        status: true,
        authorId: user1.id,
      },
      {
        title: 'Третья новость от Bob',
        text: 'Ещё одна новость, созданная пользователем Bob.',
        url: 'bob-news-3',
        status: true,
        authorId: user2.id,
      },
    ],
  });

  console.log('Данные успешно загружены с использованием Argon2 для хеширования паролей');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

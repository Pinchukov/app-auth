import { Injectable, OnModuleDestroy } from '@nestjs/common';

// Интерфейс для записи о заблокированном IP-адресе с временем истечения блокировки
interface BlockedIpEntry {
  expiresAt: number; // Timestamp (в мс), когда блокировка должна быть снята
}

@Injectable()
// Сервис для управления блокировкой IP-адресов
// Реализует логику временной блокировки IP с очисткой просроченных записей
export class IpBlocklistService implements OnModuleDestroy {
  // Внутренний Map хранит пары: IP-адрес -> данные о блокировке
  private blockedIps: Map<string, BlockedIpEntry> = new Map();

  // Таймер для периодической очистки устаревших блокировок
  private cleanupInterval: NodeJS.Timeout;

  constructor() {
    // Запускаем периодическую очистку заблокированных IP каждые 10 минут (600000 мс)
    this.cleanupInterval = setInterval(() => this.cleanup(), 10 * 60 * 1000);
  }

  /**
   * Проверяет, заблокирован ли IP в текущий момент
   * @param ip - IP-адрес для проверки
   * @returns true, если IP заблокирован и блокировка ещё не истекла, иначе false
   */
  isBlocked(ip: string): boolean {
    const entry = this.blockedIps.get(ip);
    if (!entry) return false; // Нет записи — IP не заблокирован

    // Если время блокировки истекло — снимаем блокировку и возвращаем false
    if (Date.now() > entry.expiresAt) {
      this.blockedIps.delete(ip);
      return false;
    }

    // Блокировка ещё активна
    return true;
  }

  /**
   * Блокирует IP-адрес на указанный период времени (TTL)
   * @param ip - IP-адрес для блокировки
   * @param ttlSeconds - время блокировки в секундах
   */
  block(ip: string, ttlSeconds: number) {
    // Вычисляем время окончания блокировки — текущий момент + TTL
    const expiresAt = Date.now() + ttlSeconds * 1000;
    this.blockedIps.set(ip, { expiresAt }); // Сохраняем в Map
  }

  /**
   * Убирает блокировку с указанного IP-адреса досрочно
   * @param ip - IP-адрес для разблокировки
   */
  unblock(ip: string) {
    this.blockedIps.delete(ip);
  }

  /**
   * Возвращает количество в данный момент заблокированных IP-адресов
   */
  getBlockedIpCount(): number {
    return this.blockedIps.size;
  }

  /**
   * Приватный метод очистки устаревших записей блокировки
   * Проходит по всем записям и удаляет те, у которых истекло время блокировки
   */
  private cleanup() {
    const now = Date.now();
    for (const [ip, entry] of this.blockedIps.entries()) {
      if (entry.expiresAt < now) {
        this.blockedIps.delete(ip);
      }
    }
  }

  /**
   * Жизненный цикл NestJS: вызывается при остановке/удалении модуля
   * Здесь останавливаем таймер для очистки, чтобы избежать утечек памяти
   */
  onModuleDestroy() {
    clearInterval(this.cleanupInterval);
  }
}

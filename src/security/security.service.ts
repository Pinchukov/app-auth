import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { IpBlocklistService } from './ip-blocklist.service';
import { SuspiciousActivityLogService } from './suspicious-activity-log.service';

@Injectable()
// Сервис безопасности приложения, который управляет:
// - проверкой заблокированных IP-адресов,
// - регистрацией подозрительной активности,
// - блокировкой IP при необходимости.
export class SecurityService {
  // Логгер для записи событий и ошибок, с указанием имени класса
  private readonly logger = new Logger(SecurityService.name);

  // Время блокировки IP (в секундах)
  private readonly blockDuration: number;

  // Флаг, включена ли блокировка IP подозрительных адресов (из конфигурации)
  private readonly blockIpEnabled: boolean;

  // Флаг, нужно ли логировать подозрительную активность (из конфигурации)
  private readonly logSuspicious: boolean;

  constructor(
    private readonly configService: ConfigService,
    private readonly ipBlocklistService: IpBlocklistService,
    private readonly suspiciousActivityLogService: SuspiciousActivityLogService,
  ) {
    // Получаем конфигурационные значения из ConfigService
    // Флаг блокировки IP: строка 'true' -> true, иначе false
    this.blockIpEnabled =
      this.configService.get('BLOCK_SUSPICIOUS_IP_ENABLED') === 'true';

    // Получаем длительность блокировки IP из конфига, если не задано — по умолчанию 3600 сек (1 час)
    this.blockDuration = Number(
      this.configService.get('BLOCK_SUSPICIOUS_IP_TTL') ?? 3600,
    );

    // Флаг логирования подозрительной активности
    this.logSuspicious =
      this.configService.get('LOG_SUSPICIOUS_ACTIVITY') === 'true';
  }

  /**
   * Проверка, заблокирован ли IP-адрес
   * @param ip - IP адрес для проверки
   * @returns true, если IP заблокирован, иначе false
   */
  isBlocked(ip: string): boolean {
    return this.ipBlocklistService.isBlocked(ip);
  }

  /**
   * Логирование подозрительной активности
   * - Логирует в консоль предупреждения, если включено логирование
   * - Записывает запись в базу данных через SuspiciousActivityLogService
   * - При включенной блокировке, добавляет IP в блоклист на заданное время
   *
   * @param ip - IP адрес подозрительной активности
   * @param reason - причина, почему активность считается подозрительной
   * @param metadata - дополнительная информация (userAgent, url, userId и др.)
   */
  async logSuspiciousActivity(ip: string, reason: string, metadata?: any) {
    // Логируем предупреждения в консоль, если включено
    if (this.logSuspicious) {
      this.logger.warn(`Подозрительная активность с IP ${ip}: ${reason}`);
      if (metadata) {
        this.logger.warn(`Доп. информация: ${JSON.stringify(metadata)}`);
      }
    }

    // Пытаемся записать информацию о подозрительной активности в базу
    try {
      await this.suspiciousActivityLogService.create({
        ip,
        reason,
        userAgent: metadata?.userAgent,
        url: metadata?.url,
        userId: metadata?.userId,
      });
    } catch (e) {
      // Логируем ошибку записи в базу, не прерывая основного потока
      this.logger.error('Ошибка записи подозрительной активности в базу', e);
    }

    // Если включена блокировка IP
    if (this.blockIpEnabled) {
      // Добавляем IP в блоклист с длительностью blockDuration
      this.ipBlocklistService.block(ip, this.blockDuration);
      this.logger.warn(`IP ${ip} был заблокирован на ${this.blockDuration} секунд.`);
    }
  }
}

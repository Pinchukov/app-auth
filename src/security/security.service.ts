import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { IpBlocklistService } from './ip-blocklist.service';
import { SuspiciousActivityLogService } from './suspicious-activity-log.service';

interface SuspiciousActivityMetadata {
  userAgent?: string;
  url?: string;
  userId?: string | number;
  [key: string]: string | number | boolean | undefined;
}

@Injectable()
export class SecurityService {
  private readonly logger = new Logger(SecurityService.name);

  private readonly blockDuration: number;
  private readonly blockIpEnabled: boolean;
  private readonly logSuspicious: boolean;

  constructor(
    private readonly configService: ConfigService,
    private readonly ipBlocklistService: IpBlocklistService,
    private readonly suspiciousActivityLogService: SuspiciousActivityLogService,
  ) {
    this.blockIpEnabled = this.getBooleanConfig('BLOCK_SUSPICIOUS_IP_ENABLED');
    this.logSuspicious = this.getBooleanConfig('LOG_SUSPICIOUS_ACTIVITY');
    this.blockDuration = this.getNumberConfig('BLOCK_SUSPICIOUS_IP_TTL', 3600);
  }

  private getBooleanConfig(key: string, defaultValue = false): boolean {
    const val = this.configService.get<string>(key);
    if (val === undefined) return defaultValue;
    return ['true', '1', 'yes'].includes(val.toLowerCase());
  }

  private getNumberConfig(key: string, defaultValue: number): number {
    const val = Number(this.configService.get<string>(key));
    return isNaN(val) ? defaultValue : val;
  }

  /**
   * Проверка, заблокирован ли IP-адрес (синхронный метод!
   */
  isBlocked(ip: string): boolean {
    // Убираем await, поскольку метод синхронный
    return this.ipBlocklistService.isBlocked(ip);
  }

  /**
   * Логирование подозрительной активности
   */
  async logSuspiciousActivity(ip: string, reason: string, metadata?: SuspiciousActivityMetadata) {
    if (this.logSuspicious) {
      this.logger.warn(`Подозрительная активность с IP ${ip}: ${reason}`);

      if (metadata) {
        try {
          this.logger.warn(`Доп. информация: ${JSON.stringify(metadata)}`);
        } catch {
          this.logger.warn('Доп. информация не может быть сериализована');
        }
      }
    }

    // Приводим userId к числу или undefined
    let userIdNumber: number | undefined = undefined;
    if (metadata?.userId !== undefined) {
      if (typeof metadata.userId === 'number') {
        userIdNumber = metadata.userId;
      } else if (typeof metadata.userId === 'string') {
        const parsed = parseInt(metadata.userId, 10);
        if (!isNaN(parsed)) {
          userIdNumber = parsed;
        }
      }
    }

    try {
      await this.suspiciousActivityLogService.create({
        ip,
        reason,
        userAgent: metadata?.userAgent,
        url: metadata?.url,
        userId: userIdNumber,
      });
    } catch (e) {
      this.logger.error('Ошибка записи подозрительной активности в базу', e);
    }

    if (this.blockIpEnabled) {
      this.ipBlocklistService.block(ip, this.blockDuration);
      this.logger.warn(`IP ${ip} был заблокирован на ${this.blockDuration} секунд.`);
    }
  }
}

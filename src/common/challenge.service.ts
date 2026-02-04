import { redis } from '../config/redis';

export class ChallengeService {
  async set(key: string, value: string) {
    await redis.set(key, value, 'EX', 300);
  }

  async get(key: string) {
    return redis.get(key);
  }

  async del(key: string) {
    await redis.del(key);
  }
}

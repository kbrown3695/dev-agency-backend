// Redis Types Definition
export interface CacheOptions {
  EX?: number; // Expire time in seconds
  PX?: number; // Expire time in milliseconds
  EXAT?: number; // Expire timestamp in seconds
  PXAT?: number; // Expire timestamp in milliseconds
  NX?: boolean; // Only set the key if it does not exist
  XX?: boolean; // Only set the key if it already exists
  KEEPTTL?: boolean; // Retain the time to live associated with the key
  GET?: boolean; // Return the old string stored at key, or nil if key did not exist
}

export interface RedisStatus {
  isConnected: boolean;
  isUsingFallback: boolean;
  environment: string;
  url: string;
  memoryCacheSize: number | null;
}

export interface CacheResult<T = any> {
  data: T;
  cached: boolean;
  timestamp: number;
  ttl?: number;
}

export interface RedisConfig {
  url?: string;
  host?: string;
  port?: number;
  password?: string;
  db?: number;
  tls?: any;
  socket?: {
    connectTimeout?: number;
    noDelay?: boolean;
    keepAlive?: number;
  };
}

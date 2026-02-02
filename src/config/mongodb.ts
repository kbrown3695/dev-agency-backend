// src/config/mongodb.ts
import {
  MongoClient,
  Db,
  Collection,
  Document,
  WithId,
  ObjectId,
  OptionalUnlessRequiredId,
} from 'mongodb';
import dotenv from 'dotenv';

dotenv.config();

// MongoDB URI
const MONGODB_URI =
  process.env['DATABASE_URL'] || 'mongodb://localhost:27017/dev_agency';

// Database name
const DB_NAME = process.env['DB_NAME'] || 'dev_agency';

// Singleton pattern for MongoDB connection
class MongoDBClient {
  private static instance: MongoDBClient;
  private client: MongoClient | null = null;
  private db: Db | null = null;
  private isConnecting = false;
  private connectionPromise: Promise<void> | null = null;

  private constructor() {}

  public static getInstance(): MongoDBClient {
    if (!MongoDBClient.instance) {
      MongoDBClient.instance = new MongoDBClient();
    }
    return MongoDBClient.instance;
  }

  /**
   * Connect to MongoDB
   */
  public async connect(): Promise<Db> {
    // If already connected, return the database
    if (this.db) {
      return this.db;
    }

    // If connecting in progress, wait for it
    if (this.isConnecting && this.connectionPromise) {
      await this.connectionPromise;
      return this.db!;
    }

    // Start new connection
    this.isConnecting = true;
    this.connectionPromise = this.createConnection();
    await this.connectionPromise;
    return this.db!;
  }

  private async createConnection(): Promise<void> {
    try {
      console.log('🔗 Connecting to MongoDB...');

      // For MongoDB Atlas, you might need additional options
      const options = {
        // MongoDB Atlas connection options
        maxPoolSize: parseInt(process.env['DATABASE_MAX_POOL_SIZE'] || '10'),
        minPoolSize: parseInt(process.env['DATABASE_MIN_POOL_SIZE'] || '5'),
        connectTimeoutMS: 10000,
        socketTimeoutMS: 45000,
        // Add replica set if needed
        ...(process.env['MONGODB_REPLICA_SET']
          ? { replicaSet: process.env['MONGODB_REPLICA_SET'] }
          : {}),
      };

      // Create MongoDB client
      this.client = await MongoClient.connect(MONGODB_URI, options);
      this.db = this.client.db(DB_NAME);

      console.log(`✅ MongoDB connected successfully to database: ${DB_NAME}`);

      // Set up event listeners
      this.client.on('serverClosed', () => {
        console.log('🔌 MongoDB connection closed');
        this.cleanup();
      });

      this.client.on('error', (error: any) => {
        console.error('❌ MongoDB connection error:', error);
        this.cleanup();
      });

      // Test the connection with a ping
      await this.db.command({ ping: 1 });
      console.log('✅ MongoDB ping successful');
    } catch (error) {
      console.error('❌ MongoDB connection failed:', error);
      this.cleanup();
      throw error;
    } finally {
      this.isConnecting = false;
      this.connectionPromise = null;
    }
  }

  /**
   * Get database instance
   */
  public getDatabase(): Db {
    if (!this.db) {
      throw new Error('Database not connected. Call connect() first.');
    }
    return this.db;
  }

  /**
   * Get collection instance
   */
  public getCollection<T extends Document>(
    collectionName: string,
  ): Collection<T> {
    return this.getDatabase().collection<T>(collectionName);
  }

  /**
   * Run MongoDB aggregation pipeline
   */
  public async aggregate<T extends Document>(
    collectionName: string,
    pipeline: any[],
  ): Promise<WithId<T>[]> {
    const collection = this.getCollection<T>(collectionName);
    return await collection.aggregate<WithId<T>>(pipeline).toArray();
  }

  /**
   * Create MongoDB index
   */
  public async createIndex(
    collectionName: string,
    field: string,
    options: any = {},
  ): Promise<string> {
    const collection = this.getCollection(collectionName);
    return await collection.createIndex(field, options);
  }

  /**
   * Create text index for search
   */
  public async createTextIndex(
    collectionName: string,
    fields: string[],
    options: any = {},
  ): Promise<string> {
    const collection = this.getCollection(collectionName);
    const indexSpec: any = {};
    fields.forEach((field) => {
      indexSpec[field] = 'text';
    });
    return await collection.createIndex(indexSpec, options);
  }

  /**
   * Full-text search
   */
  public async searchText<T extends Document>(
    collectionName: string,
    searchText: string,
    projection: any = {},
    limit: number = 50,
  ): Promise<WithId<T>[]> {
    const collection = this.getCollection<T>(collectionName);
    const cursor = collection.find(
      { $text: { $search: searchText } },
      { projection },
    );
    return await cursor.limit(limit).toArray();
  }

  /**
   * Find documents
   */
  public async find<T extends Document>(
    collectionName: string,
    filter: any = {},
    options: any = {},
  ): Promise<WithId<T>[]> {
    const collection = this.getCollection<T>(collectionName);
    return await collection.find(filter, options).toArray();
  }

  /**
   * Find one document
   */
  public async findOne<T extends Document>(
    collectionName: string,
    filter: any = {},
    options: any = {},
  ): Promise<WithId<T> | null> {
    const collection = this.getCollection<T>(collectionName);
    return await collection.findOne(filter, options);
  }

  /**
   * Insert one document
   */
  public async insertOne<T extends Document>(
    collectionName: string,
    document: OptionalUnlessRequiredId<T>,
    options: any = {},
  ) {
    const collection = this.getCollection<T>(collectionName);
    return await collection.insertOne(document, options);
  }

  /**
   * Update one document
   */
  public async updateOne<T extends Document>(
    collectionName: string,
    filter: any,
    update: any,
    options: any = {},
  ) {
    const collection = this.getCollection<T>(collectionName);
    return await collection.updateOne(filter, update, options);
  }

  /**
   * Delete one document
   */
  public async deleteOne<T extends Document>(
    collectionName: string,
    filter: any,
    options: any = {},
  ) {
    const collection = this.getCollection<T>(collectionName);
    return await collection.deleteOne(filter, options);
  }

  /**
   * Count documents
   */
  public async countDocuments<T extends Document>(
    collectionName: string,
    filter: any = {},
  ): Promise<number> {
    const collection = this.getCollection<T>(collectionName);
    return await collection.countDocuments(filter);
  }

  /**
   * Bulk write operations
   */
  public async bulkWrite(collectionName: string, operations: any[]) {
    const collection = this.getCollection(collectionName);
    return await collection.bulkWrite(operations);
  }

  /**
   * Start a MongoDB session for transactions
   * Note: MongoDB requires replica set for transactions
   */
  public async startSession() {
    if (!this.client) {
      throw new Error('Client not connected');
    }
    return this.client.startSession();
  }

  /**
   * Execute transaction
   */
  public async withTransaction<T>(
    fn: (session: any) => Promise<T>,
  ): Promise<T> {
    const session = await this.startSession();

    try {
      let result: T;
      await session.withTransaction(async () => {
        result = await fn(session);
      });
      return result!;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Get database stats
   */
  public async getDatabaseStats() {
    return await this.getDatabase().stats();
  }

  /**
   * Get collection stats
   */
  public async getCollectionStats(collectionName: string) {
    return await this.getDatabase().command({
      collStats: collectionName,
    });
  }

  /**
   * List all collections
   */
  public async listCollections() {
    return await this.getDatabase().listCollections().toArray();
  }

  /**
   * Close the connection
   */
  public async disconnect(): Promise<void> {
    if (this.client) {
      await this.client.close();
      console.log('🔌 MongoDB connection closed');
      this.cleanup();
    }
  }

  /**
   * Clean up resources
   */
  private cleanup(): void {
    this.client = null;
    this.db = null;
    this.isConnecting = false;
    this.connectionPromise = null;
  }

  /**
   * Check if connected
   */
  public isConnected(): boolean {
    return !!this.db;
  }

  /**
   * Health check
   */
  public async healthCheck(): Promise<boolean> {
    try {
      if (!this.db) {
        return false;
      }
      await this.db.command({ ping: 1 });
      return true;
    } catch (error) {
      console.error('MongoDB health check failed:', error);
      return false;
    }
  }
}

// Export singleton instance
export const mongodb = MongoDBClient.getInstance();

// Define document type for MongoDB operations
export type MongoDocument<T = any> = T & {
  _id: ObjectId;
  createdAt?: Date;
  updatedAt?: Date;
};

// Convenience functions for common operations
export const mongoUtils = {
  /**
   * Convert string to ObjectId
   */
  toObjectId(id: string): ObjectId {
    return new ObjectId(id);
  },

  /**
   * Check if string is valid ObjectId
   */
  isValidObjectId(id: string): boolean {
    return ObjectId.isValid(id);
  },

  /**
   * Format MongoDB document for API response
   */
  formatDocument<T extends { _id?: ObjectId }>(
    doc: T | null,
  ): (Omit<T, '_id'> & { id: string }) | null {
    if (!doc) return null;

    const { _id, ...rest } = doc;
    return {
      id: _id?.toString() || '',
      ...rest,
    } as Omit<T, '_id'> & { id: string };
  },

  /**
   * Format multiple documents
   */
  formatDocuments<T extends { _id?: ObjectId }>(
    docs: T[],
  ): (Omit<T, '_id'> & { id: string })[] {
    return docs.map((doc) => this.formatDocument(doc)!);
  },

  /**
   * Create MongoDB filter with ObjectId
   */
  createIdFilter(id: string): { _id: ObjectId } {
    return { _id: this.toObjectId(id) };
  },

  /**
   * Generate MongoDB aggregation pipeline for pagination
   */
  paginationPipeline(
    page: number = 1,
    limit: number = 10,
    sort: any = { createdAt: -1 },
  ): any[] {
    const skip = (page - 1) * limit;
    return [{ $sort: sort }, { $skip: skip }, { $limit: limit }];
  },

  /**
   * Create lookup pipeline for joining collections
   */
  createLookupPipeline(
    from: string,
    localField: string,
    foreignField: string,
    as: string,
  ): any {
    return {
      $lookup: {
        from,
        localField,
        foreignField,
        as,
      },
    };
  },

  /**
   * Create unwind pipeline for arrays
   */
  createUnwindPipeline(
    path: string,
    preserveNullAndEmptyArrays: boolean = false,
  ): any {
    return {
      $unwind: {
        path: `$${path}`,
        preserveNullAndEmptyArrays,
      },
    };
  },

  /**
   * Create match pipeline for filtering
   */
  createMatchPipeline(filter: any): any {
    return {
      $match: filter,
    };
  },

  /**
   * Create project pipeline for selecting fields
   */
  createProjectPipeline(projection: any): any {
    return {
      $project: projection,
    };
  },
};

// Helper to connect and get database in one call
export async function getMongoDB(): Promise<Db> {
  const db = await mongodb.connect();
  return db;
}

// Type-safe collection getter
export function getTypedCollection<T extends Document>(
  collectionName: string,
): Collection<T> {
  return mongodb.getCollection<T>(collectionName);
}

// Graceful shutdown
const gracefulShutdown = async () => {
  try {
    await mongodb.disconnect();
    console.log('MongoDB connection closed gracefully');
  } catch (error) {
    console.error('Error closing MongoDB connection:', error);
  }
};

// Handle process termination
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);
process.on('beforeExit', gracefulShutdown);

export default mongodb;

// src/db.ts
import { PrismaClient, PrismaPromise } from '@prisma/client';

// Prevent multiple instances of Prisma Client in development
const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

// Create Prisma Client instance with MongoDB-specific configuration
const prisma =
  globalForPrisma.prisma ||
  new PrismaClient({
    // MongoDB-specific configuration
    log:
      process.env['NODE_ENV'] === 'development'
        ? ['query', 'error', 'warn']
        : ['error'],
  });

// Store in global for hot-reloading in development
if (process.env['NODE_ENV'] !== 'production') {
  globalForPrisma.prisma = prisma;
}

// Connection health check
prisma
  .$connect()
  .then(() => {
    console.log('✅ MongoDB connected successfully via Prisma');
  })
  .catch((error: Error) => {
    console.error('❌ MongoDB connection failed:', error);
    process.exit(1);
  });

// Graceful shutdown
const gracefulShutdown = async () => {
  await prisma.$disconnect();
  console.log('MongoDB connection closed gracefully');
};

process.on('beforeExit', gracefulShutdown);
process.on('SIGINT', async () => {
  await gracefulShutdown();
  process.exit(0);
});
process.on('SIGTERM', async () => {
  await gracefulShutdown();
  process.exit(0);
});

// Add custom methods for common operations
(prisma as any).custom = {
  // Safe find user by email (handles errors)
  async findUserByEmail(email: string) {
    try {
      return await prisma.user.findUnique({
        where: { email },
        select: {
          id: true,
          firstName: true,
          lastName: true,
          displayName: true,
          email: true,
          passwordHash: true,
          role: true,
          emailVerified: true,
          isActive: true,
          createdAt: true,
        },
      });
    } catch (error) {
      console.error('Error finding user by email:', error);
      throw error;
    }
  },

  // Safe create user
  async createUser(userData: any) {
    try {
      return await prisma.user.create({
        data: userData,
        select: {
          id: true,
          firstName: true,
          lastName: true,
          displayName: true,
          email: true,
          role: true,
          emailVerified: true,
          isActive: true,
          createdAt: true,
        },
      });
    } catch (error) {
      console.error('Error creating user:', error);
      throw error;
    }
  },

  // Get user with vendor profile
  async getUserWithProfile(userId: string) {
    try {
      return await prisma.user.findUnique({
        where: { id: userId },
        include: {
          vendorProfile: true,
          projects: true,
          reviews: true,
          schedulesAsOrganizer: true,
          schedulesAsParticipant: true,
        },
      });
    } catch (error) {
      console.error('Error getting user with profile:', error);
      throw error;
    }
  },

  // Get active projects with details
  async getActiveProjects() {
    try {
      return await prisma.project.findMany({
        where: {
          status: {
            in: ['POSTED', 'IN_PROGRESS'],
          },
        },
        include: {
          client: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              email: true,
            },
          },
          vendor: {
            select: {
              id: true,
              companyName: true,
              rating: true,
            },
          },
          bids: {
            select: {
              id: true,
              bidAmount: true,
              status: true,
              createdAt: true,
            },
          },
        },
        orderBy: {
          createdAt: 'desc',
        },
      });
    } catch (error) {
      console.error('Error getting active projects:', error);
      throw error;
    }
  },

  // Search projects by keyword (using full-text search)
  async searchProjects(keyword: string) {
    try {
      return await prisma.project.findMany({
        where: {
          OR: [
            { title: { contains: keyword, mode: 'insensitive' } },
            { description: { contains: keyword, mode: 'insensitive' } },
          ],
        },
        include: {
          client: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              email: true,
            },
          },
        },
        orderBy: {
          createdAt: 'desc',
        },
      });
    } catch (error) {
      console.error('Error searching projects:', error);
      throw error;
    }
  },

  // Get featured vendors
  async getFeaturedVendors(limit: number = 10) {
    try {
      return await prisma.vendorProfile.findMany({
        where: {
          isFeatured: true,
          isListed: true,
        },
        include: {
          user: {
            select: {
              firstName: true,
              lastName: true,
              email: true,
            },
          },
          projects: {
            select: {
              id: true,
              title: true,
              status: true,
            },
          },
          reviews: {
            select: {
              rating: true,
              title: true,
              createdAt: true,
            },
          },
        },
        orderBy: {
          rating: 'desc',
        },
        take: limit,
      });
    } catch (error) {
      console.error('Error getting featured vendors:', error);
      throw error;
    }
  },

  // Transaction wrapper with error handling
  async transactionArray<T extends PrismaPromise<any>[]>(
    operations: T,
  ): Promise<any[]> {
    try {
      return await prisma.$transaction(operations);
    } catch (error) {
      console.error('Transaction failed:', error);
      throw error;
    }
  },

  // Get platform statistics
  async getPlatformStats() {
    try {
      const [
        totalUsers,
        totalVendors,
        totalProjects,
        activeProjects,
        completedProjects,
        totalBids,
      ] = await Promise.all([
        prisma.user.count(),
        prisma.vendorProfile.count(),
        prisma.project.count(),
        prisma.project.count({
          where: { status: { in: ['POSTED', 'IN_PROGRESS'] } },
        }),
        prisma.project.count({
          where: { status: 'COMPLETED' },
        }),
        prisma.bid.count(),
      ]);

      return {
        totalUsers,
        totalVendors,
        totalProjects,
        activeProjects,
        completedProjects,
        totalBids,
        completionRate:
          totalProjects > 0 ? (completedProjects / totalProjects) * 100 : 0,
      };
    } catch (error) {
      console.error('Error getting platform stats:', error);
      throw error;
    }
  },

  // Manual query logging
  async logQuery(
    operation: string,
    model: string,
    duration: number,
    success = true,
  ) {
    if (process.env['NODE_ENV'] === 'development') {
      const status = success ? '✅' : '❌';
      console.log(`${status} [${model}.${operation}] - ${duration}ms`);
    }
  },
};

console.log('🔍 db.ts: Prisma instance created and ready');

export default prisma;

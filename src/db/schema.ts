import { sql } from 'drizzle-orm'
import {
  index,
  integer,
  sqliteTable,
  text,
  uniqueIndex,
} from 'drizzle-orm/sqlite-core'

export const authUsers = sqliteTable('user', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  email: text('email').notNull().unique(),
  emailVerified: integer('emailVerified', { mode: 'boolean' }).notNull(),
  image: text('image'),
  createdAt: integer('createdAt', { mode: 'timestamp_ms' }).notNull(),
  updatedAt: integer('updatedAt', { mode: 'timestamp_ms' }).notNull(),
})

export const authSessions = sqliteTable(
  'session',
  {
    id: text('id').primaryKey(),
    expiresAt: integer('expiresAt', { mode: 'timestamp_ms' }).notNull(),
    token: text('token').notNull().unique(),
    createdAt: integer('createdAt', { mode: 'timestamp_ms' }).notNull(),
    updatedAt: integer('updatedAt', { mode: 'timestamp_ms' }).notNull(),
    ipAddress: text('ipAddress'),
    userAgent: text('userAgent'),
    userId: text('userId')
      .notNull()
      .references(() => authUsers.id, { onDelete: 'cascade' }),
  },
  (table) => ({
    userIdIdx: index('session_userId_idx').on(table.userId),
  }),
)

export const authAccounts = sqliteTable(
  'account',
  {
    id: text('id').primaryKey(),
    accountId: text('accountId').notNull(),
    providerId: text('providerId').notNull(),
    userId: text('userId')
      .notNull()
      .references(() => authUsers.id, { onDelete: 'cascade' }),
    accessToken: text('accessToken'),
    refreshToken: text('refreshToken'),
    idToken: text('idToken'),
    accessTokenExpiresAt: integer('accessTokenExpiresAt', {
      mode: 'timestamp_ms',
    }),
    refreshTokenExpiresAt: integer('refreshTokenExpiresAt', {
      mode: 'timestamp_ms',
    }),
    scope: text('scope'),
    password: text('password'),
    createdAt: integer('createdAt', { mode: 'timestamp_ms' }).notNull(),
    updatedAt: integer('updatedAt', { mode: 'timestamp_ms' }).notNull(),
  },
  (table) => ({
    userIdIdx: index('account_userId_idx').on(table.userId),
    providerAccountIdx: uniqueIndex('account_provider_account_unique').on(
      table.providerId,
      table.accountId,
    ),
  }),
)

export const authVerifications = sqliteTable(
  'verification',
  {
    id: text('id').primaryKey(),
    identifier: text('identifier').notNull(),
    value: text('value', { mode: 'json' }).notNull(),
    expiresAt: integer('expiresAt', { mode: 'timestamp_ms' }).notNull(),
    createdAt: integer('createdAt', { mode: 'timestamp_ms' }).notNull(),
    updatedAt: integer('updatedAt', { mode: 'timestamp_ms' }).notNull(),
  },
  (table) => ({
    identifierIdx: index('verification_identifier_idx').on(table.identifier),
  }),
)

export const uploads = sqliteTable(
  'uploads',
  {
    id: text('id').primaryKey(),
    ownerUserId: text('owner_user_id'),
    ownerAnonId: text('owner_anon_id'),
    expiresAt: text('expires_at'),
    r2Key: text('r2_key').notNull(),
    publicUrl: text('public_url').notNull(),
    mimeType: text('mime_type').notNull(),
    sizeBytes: integer('size_bytes', { mode: 'number' }).notNull(),
    thumbR2Key: text('thumb_r2_key'),
    webpR2Key: text('webp_r2_key'),
    webpSizeBytes: integer('webp_size_bytes', { mode: 'number' }),
    optimizationStatus: text('optimization_status', {
      enum: ['pending', 'processing', 'completed', 'failed'],
    })
      .notNull()
      .default('pending'),
    optimizedAt: text('optimized_at'),
    width: integer('width', { mode: 'number' }),
    height: integer('height', { mode: 'number' }),
    sha256: text('sha256'),
    description: text('description'),
    copyCount: integer('copy_count', { mode: 'number' }).notNull().default(0),
    createdAt: text('created_at')
      .notNull()
      .default(sql`CURRENT_TIMESTAMP`),
    updatedAt: text('updated_at')
      .notNull()
      .default(sql`CURRENT_TIMESTAMP`),
    deletedAt: text('deleted_at'),
  },
  (table) => ({
    r2KeyUnique: uniqueIndex('uploads_r2_key_unique').on(table.r2Key),
    ownerCreatedIdx: index('idx_uploads_owner_created').on(
      table.ownerUserId,
      table.createdAt,
    ),
    ownerAnonCreatedIdx: index('idx_uploads_owner_anon_created').on(
      table.ownerAnonId,
      table.createdAt,
    ),
    createdIdx: index('idx_uploads_created').on(table.createdAt),
    expiresAtIdx: index('idx_uploads_expires_at')
      .on(table.expiresAt)
      .where(sql`${table.expiresAt} IS NOT NULL`),
  }),
)

export const uploadCopyEvents = sqliteTable(
  'upload_copy_events',
  {
    id: text('id').primaryKey(),
    uploadId: text('upload_id')
      .notNull()
      .references(() => uploads.id, { onDelete: 'cascade' }),
    actorUserId: text('actor_user_id'),
    copiedFormat: text('copied_format', {
      enum: ['direct', 'markdown', 'bbcode'],
    }).notNull(),
    copiedAt: text('copied_at')
      .notNull()
      .default(sql`CURRENT_TIMESTAMP`),
    source: text('source', {
      enum: ['uploader', 'library', 'detail'],
    }).notNull(),
  },
  (table) => ({
    uploadCopiedAtIdx: index('idx_upload_copy_events_upload_copied_at').on(
      table.uploadId,
      table.copiedAt,
    ),
  }),
)

export const requestRateLimits = sqliteTable(
  'request_rate_limits',
  {
    id: text('id').primaryKey(),
    operation: text('operation').notNull(),
    scope: text('scope').notNull(),
    scopeId: text('scope_id').notNull(),
    windowStartedAt: integer('window_started_at', { mode: 'number' }).notNull(),
    requestCount: integer('request_count', { mode: 'number' })
      .notNull()
      .default(1),
    createdAt: text('created_at')
      .notNull()
      .default(sql`CURRENT_TIMESTAMP`),
    updatedAt: text('updated_at')
      .notNull()
      .default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => ({
    operationScopeWindowIdx: index(
      'idx_request_rate_limits_operation_scope',
    ).on(table.operation, table.scope, table.windowStartedAt),
    windowStartedAtIdx: index('idx_request_rate_limits_window_started_at').on(
      table.windowStartedAt,
    ),
  }),
)

export type Upload = typeof uploads.$inferSelect
export type NewUpload = typeof uploads.$inferInsert

export type UploadCopyEvent = typeof uploadCopyEvents.$inferSelect
export type NewUploadCopyEvent = typeof uploadCopyEvents.$inferInsert

export type RequestRateLimit = typeof requestRateLimits.$inferSelect
export type NewRequestRateLimit = typeof requestRateLimits.$inferInsert

export type AuthUser = typeof authUsers.$inferSelect
export type NewAuthUser = typeof authUsers.$inferInsert

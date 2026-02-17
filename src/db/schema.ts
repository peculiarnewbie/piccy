import { sql } from 'drizzle-orm'
import {
  index,
  integer,
  sqliteTable,
  text,
  uniqueIndex,
} from 'drizzle-orm/sqlite-core'

export const uploads = sqliteTable(
  'uploads',
  {
    id: text('id').primaryKey(),
    ownerUserId: text('owner_user_id'),
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

export type Upload = typeof uploads.$inferSelect
export type NewUpload = typeof uploads.$inferInsert

export type UploadCopyEvent = typeof uploadCopyEvents.$inferSelect
export type NewUploadCopyEvent = typeof uploadCopyEvents.$inferInsert

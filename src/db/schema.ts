import {
  sqliteTable,
  text,
  integer,
  blob,
  index,
} from "drizzle-orm/sqlite-core";
export const devices = sqliteTable(
  "devices",
  {
    udid: text("udid").primaryKey(),
    serialNumber: text("serial_number"),
    deviceName: text("device_name"),
    productName: text("product_name"),
    model: text("model"),
    osVersion: text("os_version"),
    buildVersion: text("build_version"),
    topic: text("topic"),
    pushToken: blob("push_token", { mode: "buffer" }),
    pushTokenHex: text("push_token_hex"),
    pushMagic: text("push_magic"),
    unlockToken: blob("unlock_token", { mode: "buffer" }),
    enrollmentId: text("enrollment_id"),
    certFingerprint: text("cert_fingerprint").notNull(),
    awaitingConfiguration: integer("awaiting_configuration", {
      mode: "boolean",
    }),
    authenticatedAt: integer("authenticated_at"),
    tokenUpdatedAt: integer("token_updated_at"),
    lastSeenAt: integer("last_seen_at"),
    unenrolledAt: integer("unenrolled_at"),
    createdAt: integer("created_at").notNull(),
    updatedAt: integer("updated_at").notNull(),
    platform: text("platform").notNull(),
    accessRights: integer("access_rights").notNull(),
    pushDeadAt: integer("push_dead_at"),
  },
  (t) => [index("device_fingerprint").on(t.certFingerprint)],
);
export const checkinEvents = sqliteTable(
  "checkin_events",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    udid: text("udid"),
    messageType: text("message_type"),
    rawBody: blob("raw_body", { mode: "buffer" }),
    parsed: text("parsed"),
    receivedAt: integer("received_at").notNull(),
    peerCertCn: text("peer_cert_cn"),
    httpStatusReturned: integer("http_status_returned"),
  },
  (t) => [index("checkin_device_time").on(t.udid, t.receivedAt)],
);
export const userChannels = sqliteTable("user_channels", {
  id: text("id").primaryKey(),
  udid: text("udid")
    .notNull()
    .references(() => devices.udid),
  userId: text("user_id").notNull(),
  pushToken: blob("push_token", { mode: "buffer" }),
  pushMagic: text("push_magic"),
  updatedAt: integer("updated_at").notNull(),
});

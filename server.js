// server.js
"use strict";

const express = require("express");
const http    = require("http");
const { Server } = require("socket.io");

const app    = express();
const server = http.createServer(app);

// ─── Constants ─────────────────────────────────────────────────────────────
// Security and validation
const DEFAULT_ROOM      = "default-room";
const DEFAULT_AVATAR    = "/avatars/avatar1.jpg";
const MAX_NAME_LENGTH   = 64;
const MAX_VOTE_LENGTH   = 16;
const MAX_BACKLOG_ITEMS = 200;
const MAX_ITEM_LENGTH   = 256;

// Timing (in milliseconds)
const ROOM_TTL_MS              = 4 * 60 * 60 * 1000; // 4 hours — prune idle rooms
const ROOM_PRUNE_INTERVAL_MS   = 30 * 60 * 1000;   // Check every 30 minutes
const GRACEFUL_SHUTDOWN_TIMEOUT_MS = 8000;         // Force-exit after 8 seconds

// Rate-limiting: max events per socket per window
const RATE_LIMIT_WINDOW_MS = 5000;
const RATE_LIMIT_MAX       = 20; // max events in that window

// CORS Configuration
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "http://localhost:3000").split(",").map(o => o.trim());

const io = new Server(server, {
  cors: {
    origin: ALLOWED_ORIGINS,
    methods: ["GET", "POST"],
    credentials: true
  }
});

app.use(express.static("public"));

// ─── Structured Logging ────────────────────────────────────────────────────
/**
 * Structured logger for production-ready logging
 */
const logger = {
  info: (msg, meta = {}) => {
    console.log(JSON.stringify({ level: "INFO", msg, timestamp: new Date().toISOString(), ...meta }));
  },
  error: (msg, error = null, meta = {}) => {
    const errorData = error instanceof Error ? { message: error.message, stack: error.stack } : error;
    console.error(JSON.stringify({ level: "ERROR", msg, timestamp: new Date().toISOString(), error: errorData, ...meta }));
  },
  warn: (msg, meta = {}) => {
    console.warn(JSON.stringify({ level: "WARN", msg, timestamp: new Date().toISOString(), ...meta }));
  }
};

// ─── Room state ───────────────────────────────────────────────────────────
//
// rooms[roomId] = {
//   revealed      : boolean,
//   votes         : { [socketId]: { name, value, avatar } },
//   backlog       : { items: string[], currentIndex: number },
//   lastActivity  : number  (Date.now())
// }
//
// Key design: votes are keyed by socket.id, not by name.
// This prevents two users with the same name overwriting each other.

const rooms = {};

/**
 * Get or create a room, updating lastActivity
 * @param {string} roomId - The room identifier
 * @returns {object} The room state object
 */
function getRoom(roomId) {
  if (!rooms[roomId]) {
    rooms[roomId] = {
      revealed: false,
      votes: {},
      backlog: { items: [], currentIndex: -1 },
      lastActivity: Date.now(),
    };
  } else {
    rooms[roomId].lastActivity = Date.now();
  }
  return rooms[roomId];
}

/**
 * Convert room state for client: transform socket-id keys to name keys
 * so the client rendering code stays unchanged
 * @param {object} room - The server room state
 * @returns {object} Client-safe room state
 */
function roomForClient(room) {
  const votes = {};
  for (const entry of Object.values(room.votes)) {
    votes[entry.name] = { value: entry.value, avatar: entry.avatar };
  }
  return { revealed: room.revealed, votes, backlog: room.backlog };
}

// Prune rooms idle longer than ROOM_TTL_MS
setInterval(() => {
  const now = Date.now();
  const roomsBefore = Object.keys(rooms).length;
  
  for (const [id, room] of Object.entries(rooms)) {
    if (now - room.lastActivity > ROOM_TTL_MS) {
      delete rooms[id];
    }
  }
  
  const roomsAfter = Object.keys(rooms).length;
  if (roomsBefore > roomsAfter) {
    logger.info("Room pruning completed", { roomsBefore, roomsAfter, pruned: roomsBefore - roomsAfter });
  }
}, ROOM_PRUNE_INTERVAL_MS);

// ─── Input Sanitization Helpers ─────────────────────────────────────────────

/**
 * Sanitize and validate a user name
 * @param {*} raw - Raw input
 * @returns {string} Sanitized name or "Anonymous"
 */
function sanitiseName(raw) {
  return String(raw || "").trim().slice(0, MAX_NAME_LENGTH) || "Anonymous";
}

/**
 * Sanitize and validate a vote value
 * @param {*} raw - Raw input
 * @returns {string} Sanitized vote value
 */
function sanitiseVote(raw) {
  return String(raw || "").trim().slice(0, MAX_VOTE_LENGTH);
}

/**
 * Sanitize and validate an avatar path
 * @param {*} raw - Raw input
 * @returns {string} Valid avatar path or default
 */
function sanitiseAvatar(raw) {
  // Only allow predefined avatar paths to prevent path traversal attacks
  if (typeof raw === "string" && /^\/avatars\/avatar\d+\.jpg$/.test(raw)) {
    return raw;
  }
  return DEFAULT_AVATAR;
}

/**
 * Sanitize and validate backlog items array
 * @param {*} raw - Raw input
 * @returns {string[]} Array of sanitized item strings
 */
function sanitiseBacklogItems(raw) {
  if (!Array.isArray(raw)) return [];
  return raw
    .slice(0, MAX_BACKLOG_ITEMS)
    .map((s) => String(s).trim().slice(0, MAX_ITEM_LENGTH))
    .filter(Boolean);
}

// ─── Rate Limiter ──────────────────────────────────────────────────────────

/**
 * Creates a rate limiter for a single socket connection
 * @returns {function} Function that returns true if event is allowed
 */
function makeRateLimiter() {
  let count     = 0;
  let windowEnd = Date.now() + RATE_LIMIT_WINDOW_MS;

  return function isAllowed() {
    const now = Date.now();
    if (now > windowEnd) {
      count     = 0;
      windowEnd = now + RATE_LIMIT_WINDOW_MS;
    }
    count++;
    return count <= RATE_LIMIT_MAX;
  };
}

// ─── Socket Event Handlers ─────────────────────────────────────────────────

io.on("connection", (socket) => {
  let currentRoom   = null;
  let currentName   = null;
  let currentAvatar = DEFAULT_AVATAR;
  let hasJoined     = false;

  const isAllowed = makeRateLimiter();

  logger.info("Socket connected", { socketId: socket.id });

  /**
   * Wrapper to ensure socket has joined a room and check rate limits
   * @param {function} fn - The handler function to execute
   */
  function requiresRoom(fn) {
    if (!currentRoom || !hasJoined) {
      socket.emit("error", "Not in a room. Please join first.");
      return;
    }
    if (!isAllowed()) {
      socket.emit("error", "Rate limit exceeded. Slow down.");
      logger.warn("Rate limit exceeded", { socketId: socket.id, roomId: currentRoom });
      return;
    }
    try {
      fn();
    } catch (error) {
      logger.error("Handler error", error, { socketId: socket.id, roomId: currentRoom });
      socket.emit("error", "An error occurred processing your request.");
    }
  }

  /**
   * Broadcast updated state to everyone in the room
   */
  function broadcastState() {
    const room = rooms[currentRoom];
    if (!room) return;
    io.to(currentRoom).emit("stateUpdate", roomForClient(room));
  }

  // ── joinRoom ───────────────────────────────────────────────────────────────
  socket.on("joinRoom", (payload) => {
    try {
      if (!payload || typeof payload !== "object") {
        socket.emit("error", "Invalid joinRoom payload.");
        return;
      }
      const { roomId, name, avatar } = payload;

      // Leave previous room — clean up stale vote entry
      if (currentRoom) {
        socket.leave(currentRoom);
        const oldRoom = rooms[currentRoom];
        if (oldRoom) {
          delete oldRoom.votes[socket.id];
          io.to(currentRoom).emit("stateUpdate", roomForClient(oldRoom));
        }
      }

      currentRoom   = sanitiseName(roomId) || DEFAULT_ROOM;
      currentName   = sanitiseName(name);
      currentAvatar = sanitiseAvatar(avatar);
      hasJoined     = true;

      socket.join(currentRoom);

      const room = getRoom(currentRoom);

      // Register presence immediately (value empty = not yet voted)
      room.votes[socket.id] = { name: currentName, value: "", avatar: currentAvatar };

      socket.emit("stateUpdate",  roomForClient(room));
      socket.emit("backlogUpdate", room.backlog);

      // Notify others that someone joined
      broadcastState();

      logger.info("User joined room", { socketId: socket.id, roomId: currentRoom, userName: currentName });
    } catch (error) {
      logger.error("Error in joinRoom", error, { socketId: socket.id });
      socket.emit("error", "Failed to join room.");
    }
  });

  // ── vote ───────────────────────────────────────────────────────────────────
  socket.on("vote", (rawValue) => {
    requiresRoom(() => {
      const room = getRoom(currentRoom);
      if (room.revealed) return; // locked after reveal
      const value = sanitiseVote(rawValue);
      room.votes[socket.id] = { name: currentName, value, avatar: currentAvatar };
      broadcastState();
      logger.info("Vote cast", { socketId: socket.id, roomId: currentRoom, value });
    });
  });

  // ── reveal ─────────────────────────────────────────────────────────────────
  socket.on("reveal", () => {
    requiresRoom(() => {
      const room = getRoom(currentRoom);
      if (room.revealed) return; // idempotent
      room.revealed = true;
      broadcastState();
      logger.info("Votes revealed", { socketId: socket.id, roomId: currentRoom, totalVotes: Object.keys(room.votes).length });
    });
  });

  // ── reset ──────────────────────────────────────────────────────────────────
  socket.on("reset", () => {
    requiresRoom(() => {
      const room = getRoom(currentRoom);
      room.revealed = false;
      // Clear votes but keep participants present (empty value)
      for (const id of Object.keys(room.votes)) {
        room.votes[id].value = "";
      }
      broadcastState();
      logger.info("Round reset", { socketId: socket.id, roomId: currentRoom });
    });
  });

  // ── setBacklog ─────────────────────────────────────────────────────────────
  socket.on("setBacklog", (payload) => {
    requiresRoom(() => {
      if (!payload || typeof payload !== "object") {
        socket.emit("error", "Invalid setBacklog payload.");
        return;
      }
      const items        = sanitiseBacklogItems(payload.items);
      const currentIndex = items.length > 0 ? 0 : -1;
      const room         = getRoom(currentRoom);
      room.backlog       = { items, currentIndex };
      io.to(currentRoom).emit("backlogUpdate", room.backlog);
      logger.info("Backlog updated", { socketId: socket.id, roomId: currentRoom, itemCount: items.length });
    });
  });

  // ── setBacklogIndex ────────────────────────────────────────────────────────
  socket.on("setBacklogIndex", (rawIndex) => {
    requiresRoom(() => {
      const room      = getRoom(currentRoom);
      const { items } = room.backlog;
      if (!items.length) return;
      const index = parseInt(rawIndex, 10);
      if (Number.isNaN(index) || index < 0 || index >= items.length) {
        socket.emit("error", "Invalid backlog index.");
        return;
      }

      room.backlog.currentIndex = index;
      room.revealed = false;
      for (const id of Object.keys(room.votes)) {
        room.votes[id].value = "";
      }

      io.to(currentRoom).emit("stateUpdate",  roomForClient(room));
      io.to(currentRoom).emit("backlogUpdate", room.backlog);
      logger.info("Backlog index changed", { socketId: socket.id, roomId: currentRoom, index, item: items[index] });
    });
  });

  // ── disconnect ─────────────────────────────────────────────────────────────
  socket.on("disconnect", () => {
    if (!currentRoom) return;
    const room = rooms[currentRoom];
    if (!room) return;
    delete room.votes[socket.id];
    io.to(currentRoom).emit("stateUpdate", roomForClient(room));
    logger.info("User disconnected", { socketId: socket.id, roomId: currentRoom, userName: currentName });
  });

  // ── error handler ──────────────────────────────────────────────────────────
  socket.on("error", (error) => {
    logger.error("Socket error", error, { socketId: socket.id, roomId: currentRoom });
  });
});

// ─── Graceful Shutdown ────────────────────────────────────────────────────────

/**
 * Graceful shutdown handler
 * @param {string} signal - The shutdown signal received
 */
function shutdown(signal) {
  logger.info("Shutdown signal received", { signal });
  
  // Notify all connected clients
  io.emit("serverShutdown", "Server is restarting. Please refresh in a moment.");
  
  server.close(() => {
    logger.info("HTTP server closed", { signal });
    process.exit(0);
  });
  
  // Force-exit after timeout if connections hang
  setTimeout(() => {
    logger.warn("Force-exiting due to timeout", { signal });
    process.exit(1);
  }, GRACEFUL_SHUTDOWN_TIMEOUT_MS).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT",  () => shutdown("SIGINT"));

// ─── Error Handler ────────────────────────────────────────────────────────

process.on("uncaughtException", (error) => {
  logger.error("Uncaught exception", error);
  process.exit(1);
});

process.on("unhandledRejection", (reason, promise) => {
  logger.error("Unhandled rejection", reason, { promise });
  process.exit(1);
});

// ─── Start Server ─────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  logger.info("Planning Poker server started", { port: PORT, environment: process.env.NODE_ENV || "development" });
});

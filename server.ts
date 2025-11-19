import { Hono } from "hono";
import { cors } from "hono/cors";
import { serveStatic } from "hono/deno";
import { 
  Account, 
  AccountCreate, 
  AccountUpdate, 
  ClaudeRequest,
  ChatCompletionRequest
} from "./types.ts";
import * as db from "./db.ts";
import * as auth from "./auth.ts";
import { convertClaudeToAmazonQRequest, convertOpenAIRequestToAmazonQ } from "./converter.ts";
import { sendChatRequest } from "./amazon_q.ts";
import { ClaudeStreamHandler } from "./stream_handler.ts";

const app = new Hono();

app.use("*", cors());

// --- Configuration ---
const ALLOWED_API_KEYS = (Deno.env.get("OPENAI_KEYS") || "")
  .split(",")
  .map(k => k.trim())
  .filter(k => k);

const MAX_ERROR_COUNT = parseInt(Deno.env.get("MAX_ERROR_COUNT") || "100");
const CONSOLE_ENABLED = (Deno.env.get("ENABLE_CONSOLE") || "true").toLowerCase() !== "false";

// --- Helpers ---

async function refreshAccessTokenInDb(accountId: string): Promise<Account> {
  const acc = await db.getAccount(accountId);
  if (!acc) throw new Error("Account not found");

  if (!acc.clientId || !acc.clientSecret || !acc.refreshToken) {
    throw new Error("Account missing credentials for refresh");
  }

  try {
    const data = await auth.refreshToken(acc.clientId, acc.clientSecret, acc.refreshToken);
    const newAccess = data.accessToken;
    const newRefresh = data.refreshToken || acc.refreshToken;
    
    await db.updateAccountTokens(accountId, newAccess, newRefresh, "success");
    
    const updated = await db.getAccount(accountId);
    return updated!;
  } catch (e: any) {
    await db.updateAccountRefreshStatus(accountId, "failed");
    throw e;
  }
}

async function resolveAccountForKey(bearerKey?: string): Promise<Account> {
  if (ALLOWED_API_KEYS.length > 0) {
    if (!bearerKey || !ALLOWED_API_KEYS.includes(bearerKey)) {
      throw new Error("Invalid or missing API key"); // 401
    }
  }

  const candidates = await db.listAccounts(true);
  if (candidates.length === 0) {
    throw new Error("No enabled account available"); // 401
  }
  
  // Random choice
  return candidates[Math.floor(Math.random() * candidates.length)];
}

function extractBearer(authHeader?: string): string | undefined {
  if (!authHeader) return undefined;
  if (authHeader.startsWith("Bearer ")) return authHeader.substring(7).trim();
  return authHeader.trim();
}

// --- Background Tasks ---

async function refreshStaleTokens() {
  try {
    const accounts = await db.listAccounts(true);
    const now = Date.now() / 1000;
    
    for (const acc of accounts) {
      let shouldRefresh = false;
      if (!acc.last_refresh_time || acc.last_refresh_status === "never") {
        shouldRefresh = true;
      } else {
        try {
          const lastTime = new Date(acc.last_refresh_time).getTime() / 1000;
          if (now - lastTime > 1500) { // 25 mins
            shouldRefresh = true;
          }
        } catch {
          shouldRefresh = true;
        }
      }

      if (shouldRefresh) {
        try {
          await refreshAccessTokenInDb(acc.id);
          console.log(`Refreshed token for ${acc.id}`);
        } catch (e) {
          console.error(`Failed to refresh ${acc.id}:`, e);
        }
      }
    }
  } catch (e) {
    console.error("Error in refreshStaleTokens:", e);
  }
}

// Deno Cron (works in Deploy)
Deno.cron("Refresh Tokens", "*/5 * * * *", refreshStaleTokens);

// --- Routes ---

app.get("/healthz", (c) => c.json({ status: "ok" }));

// Frontend
app.get("/", serveStatic({ path: "./frontend/index.html" }));

// Account Management
if (CONSOLE_ENABLED) {
  app.get("/v2/accounts", async (c) => {
    const accounts = await db.listAccounts();
    return c.json(accounts);
  });

  app.post("/v2/accounts", async (c) => {
    const body = await c.req.json<AccountCreate>();
    const acc = await db.createAccount(body);
    return c.json(acc);
  });

  app.get("/v2/accounts/:id", async (c) => {
    const id = c.req.param("id");
    const acc = await db.getAccount(id);
    if (!acc) return c.json({ error: "Not found" }, 404);
    return c.json(acc);
  });

  app.delete("/v2/accounts/:id", async (c) => {
    const id = c.req.param("id");
    const deleted = await db.deleteAccount(id);
    if (!deleted) return c.json({ error: "Not found" }, 404);
    return c.json({ deleted: id });
  });

  app.patch("/v2/accounts/:id", async (c) => {
    const id = c.req.param("id");
    const body = await c.req.json<AccountUpdate>();
    const updated = await db.updateAccount(id, body);
    if (!updated) return c.json({ error: "Not found" }, 404);
    return c.json(updated);
  });

  app.post("/v2/accounts/:id/refresh", async (c) => {
    const id = c.req.param("id");
    try {
      const acc = await refreshAccessTokenInDb(id);
      return c.json(acc);
    } catch (e: any) {
      return c.json({ error: e.message }, 502);
    }
  });
}

// Device Auth Flow
const AUTH_SESSIONS = new Map<string, any>();

if (CONSOLE_ENABLED) {
  app.post("/v2/auth/start", async (c) => {
    const body = await c.req.json<{label?: string, enabled?: boolean}>();
    try {
        const [cid, csec] = await auth.registerClientMin();
        const dev = await auth.deviceAuthorize(cid, csec);
        
        const authId = crypto.randomUUID();
        const sess = {
            clientId: cid,
            clientSecret: csec,
            deviceCode: dev.deviceCode,
            interval: dev.interval || 1,
            expiresIn: dev.expiresIn || 600,
            verificationUriComplete: dev.verificationUriComplete,
            userCode: dev.userCode,
            startTime: Math.floor(Date.now() / 1000),
            label: body.label,
            enabled: body.enabled !== false,
            status: "pending",
            error: null,
            accountId: null
        };
        AUTH_SESSIONS.set(authId, sess);
        
        return c.json({
            authId,
            verificationUriComplete: sess.verificationUriComplete,
            userCode: sess.userCode,
            expiresIn: sess.expiresIn,
            interval: sess.interval
        });
    } catch (e: any) {
        return c.json({ error: e.message }, 502);
    }
  });

  app.get("/v2/auth/status/:authId", (c) => {
      const authId = c.req.param("authId");
      const sess = AUTH_SESSIONS.get(authId);
      if (!sess) return c.json({ error: "Not found" }, 404);
      
      const now = Math.floor(Date.now() / 1000);
      const deadline = sess.startTime + Math.min(sess.expiresIn, 300); // 5 min cap
      const remaining = Math.max(0, deadline - now);
      
      return c.json({
          status: sess.status,
          remaining,
          error: sess.error,
          accountId: sess.accountId
      });
  });

  app.post("/v2/auth/claim/:authId", async (c) => {
      const authId = c.req.param("authId");
      const sess = AUTH_SESSIONS.get(authId);
      if (!sess) return c.json({ error: "Not found" }, 404);
      
      if (["completed", "timeout", "error"].includes(sess.status)) {
          return c.json({
              status: sess.status,
              accountId: sess.accountId,
              error: sess.error
          });
      }
      
      try {
          const toks = await auth.pollTokenDeviceCode(
              sess.clientId,
              sess.clientSecret,
              sess.deviceCode,
              sess.interval,
              sess.expiresIn,
              300
          );
          
          const acc = await db.createAccount({
              clientId: sess.clientId,
              clientSecret: sess.clientSecret,
              accessToken: toks.accessToken,
              refreshToken: toks.refreshToken,
              label: sess.label,
              enabled: sess.enabled
          });
          
          sess.status = "completed";
          sess.accountId = acc.id;
          
          return c.json({
              status: "completed",
              account: acc
          });
      } catch (e: any) {
          if (e.message.includes("timeout")) {
              sess.status = "timeout";
              return c.json({ error: "Timeout" }, 408);
          } else {
              sess.status = "error";
              sess.error = e.message;
              return c.json({ error: e.message }, 502);
          }
      }
  });
}

// Chat API

app.post("/v1/messages", async (c) => {
    const req = await c.req.json<ClaudeRequest>();
    const authHeader = c.req.header("Authorization");
    const bearer = extractBearer(authHeader);
    
    let account: Account;
    try {
        account = await resolveAccountForKey(bearer);
    } catch (e: any) {
        return c.json({ error: e.message }, 401);
    }

    // Convert request
    const aqRequest = convertClaudeToAmazonQRequest(req);

    // Send upstream
    async function getStream(acc: Account) {
        let access = acc.accessToken;
        if (!access) {
            const refreshed = await refreshAccessTokenInDb(acc.id);
            access = refreshed.accessToken;
        }
        if (!access) throw new Error("Access token missing");
        
        return await sendChatRequest(access, aqRequest);
    }

    try {
        let result = await getStream(account);
        
        const stream = new ReadableStream({
            async start(controller) {
                const handler = new ClaudeStreamHandler(req.model, 0);
                const encoder = new TextEncoder();
                
                try {
                    for await (const [eventType, payload] of result.eventStream) {
                        for await (const sse of handler.handleEvent(eventType, payload)) {
                            controller.enqueue(encoder.encode(sse));
                        }
                    }
                    for await (const sse of handler.finish()) {
                        controller.enqueue(encoder.encode(sse));
                    }
                    await db.updateAccountStats(account.id, true, MAX_ERROR_COUNT);
                } catch (e) {
                    await db.updateAccountStats(account.id, false, MAX_ERROR_COUNT);
                    console.error("Stream error:", e);
                    controller.error(e);
                } finally {
                    controller.close();
                }
            }
        });

        return new Response(stream, {
            headers: {
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive"
            }
        });

    } catch (e: any) {
        await db.updateAccountStats(account.id, false, MAX_ERROR_COUNT);
        return c.json({ error: e.message }, 502);
    }
});

app.post("/v1/chat/completions", async (c) => {
    const req = await c.req.json<ChatCompletionRequest>();
    const authHeader = c.req.header("Authorization");
    const bearer = extractBearer(authHeader);

    let account: Account;
    try {
        account = await resolveAccountForKey(bearer);
    } catch (e: any) {
        return c.json({ error: e.message }, 401);
    }

    const aqRequest = convertOpenAIRequestToAmazonQ(req);
    const doStream = req.stream === true;
    const model = req.model || "unknown";
    const created = Math.floor(Date.now() / 1000);
    const id = `chatcmpl-${crypto.randomUUID()}`;

    async function getStream(acc: Account) {
        let access = acc.accessToken;
        if (!access) {
            const refreshed = await refreshAccessTokenInDb(acc.id);
            access = refreshed.accessToken;
        }
        if (!access) throw new Error("Access token missing");
        
        return await sendChatRequest(access, aqRequest);
    }

    try {
        const result = await getStream(account);

        if (doStream) {
            const stream = new ReadableStream({
                async start(controller) {
                    const encoder = new TextEncoder();
                    const sendSSE = (data: any) => {
                        controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
                    };

                    try {
                        // Initial chunk
                        sendSSE({
                            id, object: "chat.completion.chunk", created, model,
                            choices: [{ index: 0, delta: { role: "assistant" }, finish_reason: null }]
                        });

                        for await (const [eventType, payload] of result.eventStream) {
                            if (CONSOLE_ENABLED) {
                                // console.log("Event Type:", eventType);
                                // console.log("Payload keys:", typeof payload === 'object' ? Object.keys(payload) : "primitive");
                            }

                            // We need to extract text from Amazon Q events
                            // Enhanced logic matching Python's _extract_text_from_event fully
                            let text = "";
                            
                            if (payload && typeof payload === 'object') {
                                // 1. Check nested content in specific keys
                                const keysToCheck = ["assistantResponseEvent", "assistantMessage", "message", "delta", "data"];
                                for (const key of keysToCheck) {
                                    if (payload[key] && typeof payload[key] === 'object') {
                                        const inner = payload[key];
                                        if (inner.content && typeof inner.content === 'string') {
                                            text = inner.content;
                                            break;
                                        }
                                    }
                                }

                                // 2. Check top-level content (string)
                                if (!text && payload.content && typeof payload.content === 'string') {
                                    text = payload.content;
                                }

                                // 3. Check lists (chunks or content)
                                if (!text) {
                                    const listKeys = ["chunks", "content"];
                                    for (const listKey of listKeys) {
                                        if (Array.isArray(payload[listKey])) {
                                            const parts = payload[listKey].map((item: any) => {
                                                if (typeof item === 'string') return item;
                                                if (typeof item === 'object') {
                                                    if (item.content && typeof item.content === 'string') return item.content;
                                                    if (item.text && typeof item.text === 'string') return item.text;
                                                }
                                                return "";
                                            });
                                            const joined = parts.join("");
                                            if (joined) {
                                                text = joined;
                                                break;
                                            }
                                        }
                                    }
                                }
                                
                                // 4. Fallback: check text/delta/payload keys if they are strings
                                if (!text) {
                                    const fallbackKeys = ["text", "delta", "payload"];
                                    for (const k of fallbackKeys) {
                                        if (payload[k] && typeof payload[k] === 'string') {
                                            text = payload[k];
                                            break;
                                        }
                                    }
                                }
                            }
                            
                            if (text) {
                                sendSSE({
                                    id, object: "chat.completion.chunk", created, model,
                                    choices: [{ index: 0, delta: { content: text }, finish_reason: null }]
                                });
                            }
                        }
                        controller.enqueue(encoder.encode("data: [DONE]\n\n"));

                        await db.updateAccountStats(account.id, true, MAX_ERROR_COUNT);
                    } catch (e) {
                        await db.updateAccountStats(account.id, false, MAX_ERROR_COUNT);
                        console.error("Stream error:", e);
                        // Try to send error in stream if possible, or just close
                        const errObj = { error: { message: String(e), type: "server_error" } };
                         controller.enqueue(encoder.encode(`data: ${JSON.stringify(errObj)}\n\n`));
                    } finally {
                        controller.close();
                    }
                }
            });

            return new Response(stream, {
                headers: {
                    "Content-Type": "text/event-stream",
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive"
                }
            });
        } else {
            // Non-streaming: accumulate
            const chunks: string[] = [];
            for await (const [_, payload] of result.eventStream) {
                let text = "";
                
                if (payload && typeof payload === 'object') {
                    // 1. Check nested content
                    const keysToCheck = ["assistantResponseEvent", "assistantMessage", "message", "delta", "data"];
                    for (const key of keysToCheck) {
                        if (payload[key] && typeof payload[key] === 'object') {
                            const inner = payload[key];
                            if (inner.content && typeof inner.content === 'string') {
                                text = inner.content;
                                break;
                            }
                        }
                    }

                    // 2. Check top-level content
                    if (!text && payload.content && typeof payload.content === 'string') {
                        text = payload.content;
                    }

                    // 3. Check lists
                    if (!text) {
                        const listKeys = ["chunks", "content"];
                        for (const listKey of listKeys) {
                            if (Array.isArray(payload[listKey])) {
                                const parts = payload[listKey].map((item: any) => {
                                    if (typeof item === 'string') return item;
                                    if (typeof item === 'object') {
                                        if (item.content && typeof item.content === 'string') return item.content;
                                        if (item.text && typeof item.text === 'string') return item.text;
                                    }
                                    return "";
                                });
                                text = parts.join("");
                                if (text) break;
                            }
                        }
                    }
                    
                    // 4. Fallback
                    if (!text) {
                        const fallbackKeys = ["text", "delta", "payload"];
                        for (const k of fallbackKeys) {
                            if (payload[k] && typeof payload[k] === 'string') {
                                text = payload[k];
                                break;
                            }
                        }
                    }
                }

                if (text) chunks.push(text);
            }
            
            if (chunks.length === 0) {
                 console.warn("No content chunks received from upstream.");
                 // If we have payload but no text, it might be an error message or empty response
            }

            const fullText = chunks.join("");
            await db.updateAccountStats(account.id, true, MAX_ERROR_COUNT);

            return c.json({
                id,
                object: "chat.completion",
                created,
                model,
                choices: [{
                    index: 0,
                    message: { role: "assistant", content: fullText },
                    finish_reason: "stop"
                }],
                usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 }
            });
        }

    } catch (e: any) {
        await db.updateAccountStats(account.id, false, MAX_ERROR_COUNT);
        return c.json({ error: e.message }, 502);
    }
});

Deno.serve(app.fetch);

import { 
  build_message_start, build_content_block_start, build_content_block_delta, 
  build_content_block_stop, build_ping, build_message_stop, 
  build_tool_use_start, build_tool_use_input_delta 
} from "./sse_builder.ts";
import { get_encoding } from "tiktoken";

// Initialize tokenizer (cl100k_base is used by gpt-4, gpt-3.5-turbo)
let ENCODING: any = null;
try {
  ENCODING = get_encoding("cl100k_base");
} catch (e) {
  console.error("Failed to load tiktoken encoding:", e);
}

function countTokens(text: string): number {
  if (!text || !ENCODING) return 0;
  try {
    return ENCODING.encode(text).length;
  } catch (e) {
    return 0;
  }
}

export class ClaudeStreamHandler {
  model: string;
  inputTokens: number;
  responseBuffer: string[];
  contentBlockIndex: number;
  contentBlockStarted: boolean;
  contentBlockStartSent: boolean;
  contentBlockStopSent: boolean;
  messageStartSent: boolean;
  conversationId: string | null;

  currentToolUse: Record<string, any> | null;
  toolInputBuffer: string[];
  toolUseId: string | null;
  toolName: string | null;
  processedToolUseIds: Set<string>;
  allToolInputs: string[];

  constructor(model: string, inputTokens: number = 0) {
    this.model = model;
    this.inputTokens = inputTokens;
    this.responseBuffer = [];
    this.contentBlockIndex = -1;
    this.contentBlockStarted = false;
    this.contentBlockStartSent = false;
    this.contentBlockStopSent = false;
    this.messageStartSent = false;
    this.conversationId = null;
    
    this.currentToolUse = null;
    this.toolInputBuffer = [];
    this.toolUseId = null;
    this.toolName = null;
    this.processedToolUseIds = new Set();
    this.allToolInputs = [];
  }

  async *handleEvent(eventType: string, payload: any): AsyncGenerator<string> {
    // 1. Message Start
    if (eventType === "initial-response") {
      if (!this.messageStartSent) {
        const convId = payload.conversationId || this.conversationId || "unknown";
        this.conversationId = convId;
        yield build_message_start(convId, this.model, this.inputTokens);
        this.messageStartSent = true;
        yield build_ping();
      }
    } 
    // 2. Content Block Delta
    else if (eventType === "assistantResponseEvent") {
      const content = payload.content || "";
      
      // Close tool use if open
      if (this.currentToolUse && !this.contentBlockStopSent) {
        yield build_content_block_stop(this.contentBlockIndex);
        this.contentBlockStopSent = true;
        this.currentToolUse = null;
      }

      // Start content block
      if (!this.contentBlockStartSent) {
        this.contentBlockIndex += 1;
        yield build_content_block_start(this.contentBlockIndex, "text");
        this.contentBlockStartSent = true;
        this.contentBlockStarted = true;
      }

      // Send delta
      if (content) {
        this.responseBuffer.push(content);
        yield build_content_block_delta(this.contentBlockIndex, content);
      }
    }
    // 3. Tool Use
    else if (eventType === "toolUseEvent") {
      const toolUseId = payload.toolUseId;
      const toolName = payload.name;
      const toolInput = payload.input || {};
      const isStop = payload.stop || false;

      // Start new tool use
      if (toolUseId && toolName && !this.currentToolUse) {
        if (this.contentBlockStartSent && !this.contentBlockStopSent) {
          yield build_content_block_stop(this.contentBlockIndex);
          this.contentBlockStopSent = true;
        }

        this.processedToolUseIds.add(toolUseId);
        this.contentBlockIndex += 1;

        yield build_tool_use_start(this.contentBlockIndex, toolUseId, toolName);

        this.contentBlockStarted = true;
        this.currentToolUse = { toolUseId, name: toolName };
        this.toolUseId = toolUseId;
        this.toolName = toolName;
        this.toolInputBuffer = [];
        this.contentBlockStopSent = false;
        this.contentBlockStartSent = true;
      }

      // Accumulate input
      if (this.currentToolUse && toolInput) {
        let fragment = "";
        if (typeof toolInput === "string") fragment = toolInput;
        else fragment = JSON.stringify(toolInput);

        this.toolInputBuffer.push(fragment);
        yield build_tool_use_input_delta(this.contentBlockIndex, fragment);
      }

      // Stop tool use
      if (isStop && this.currentToolUse) {
        const fullInput = this.toolInputBuffer.join("");
        this.allToolInputs.push(fullInput);

        yield build_content_block_stop(this.contentBlockIndex);
        this.contentBlockStopSent = true;
        this.contentBlockStarted = false;
        this.currentToolUse = null;
        this.toolUseId = null;
        this.toolName = null;
        this.toolInputBuffer = [];
      }
    }
    // 4. Assistant Response End
    else if (eventType === "assistantResponseEnd") {
      if (this.contentBlockStarted && !this.contentBlockStopSent) {
        yield build_content_block_stop(this.contentBlockIndex);
        this.contentBlockStopSent = true;
      }
    }
  }

  async *finish(): AsyncGenerator<string> {
    if (this.contentBlockStarted && !this.contentBlockStopSent) {
      yield build_content_block_stop(this.contentBlockIndex);
      this.contentBlockStopSent = true;
    }

    const fullText = this.responseBuffer.join("");
    const fullToolInput = this.allToolInputs.join("");
    const outputTokens = countTokens(fullText) + countTokens(fullToolInput);

    yield build_message_stop(this.inputTokens, outputTokens, "end_turn");
  }
}

export class EventStreamParser {
  static parseHeaders(headersData: Uint8Array): Record<string, any> {
    const headers: Record<string, any> = {};
    let offset = 0;
    const decoder = new TextDecoder("utf-8");

    while (offset < headersData.byteLength) {
      if (offset >= headersData.byteLength) break;
      const nameLength = headersData[offset];
      offset += 1;

      if (offset + nameLength > headersData.byteLength) break;
      const name = decoder.decode(headersData.subarray(offset, offset + nameLength));
      offset += nameLength;

      if (offset >= headersData.byteLength) break;
      const valueType = headersData[offset];
      offset += 1;

      if (offset + 2 > headersData.byteLength) break;
      const view = new DataView(headersData.buffer, headersData.byteOffset + offset, headersData.byteLength - offset);
      const valueLength = view.getUint16(0, false);
      offset += 2;

      if (offset + valueLength > headersData.byteLength) break;

      if (valueType === 7) {
        const value = decoder.decode(headersData.subarray(offset, offset + valueLength));
        headers[name] = value;
      } else {
        const value = headersData.subarray(offset, offset + valueLength);
        headers[name] = value;
      }
      offset += valueLength;
    }
    return headers;
  }

  static parseMessage(data: Uint8Array): { headers: Record<string, any>, payload: any, total_length: number } | null {
    if (data.byteLength < 16) return null;
    
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const totalLength = view.getUint32(0, false);
    const headersLength = view.getUint32(4, false);
    
    if (data.byteLength < totalLength) {
        // Incomplete message
        return null; 
    }
    
    const headersData = data.subarray(12, 12 + headersLength);
    const headers = EventStreamParser.parseHeaders(headersData);
    
    const payloadStart = 12 + headersLength;
    const payloadEnd = totalLength - 4; // Skip Message CRC (last 4 bytes)
    const payloadData = data.subarray(payloadStart, payloadEnd);
    
    let payload = null;
    if (payloadData.length > 0) {
        try {
            const text = new TextDecoder("utf-8").decode(payloadData);
            payload = JSON.parse(text);
        } catch {
            payload = payloadData;
        }
    }
    
    return {
        headers,
        payload,
        total_length: totalLength
    };
  }

  static async *parseStream(stream: ReadableStream<Uint8Array>): AsyncGenerator<any> {
      const reader = stream.getReader();
      let buffer = new Uint8Array(0);
      
      try {
          while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              if (value) {
                  const newBuffer = new Uint8Array(buffer.length + value.length);
                  newBuffer.set(buffer);
                  newBuffer.set(value, buffer.length);
                  buffer = newBuffer;
              }
              
              while (buffer.length >= 12) {
                  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
                  const totalLength = view.getUint32(0, false);
                  
                  if (buffer.length < totalLength) break;
                  
                  const messageData = buffer.subarray(0, totalLength);
                  buffer = buffer.subarray(totalLength);
                  
                  const message = EventStreamParser.parseMessage(messageData);
                  if (message) {
                      yield message;
                  }
              }
          }
      } finally {
          reader.releaseLock();
      }
  }
}

export function extractEventInfo(message: any): any {
    const headers = message.headers || {};
    const payload = message.payload;
    
    const eventType = headers[':event-type'] || headers['event-type'];
    const contentType = headers[':content-type'] || headers['content-type'];
    const messageType = headers[':message-type'] || headers['message-type'];
    
    return {
        event_type: eventType,
        content_type: contentType,
        message_type: messageType,
        payload: payload
    };
}
